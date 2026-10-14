// ssh-ca-web: tiny web UI to sign device keys, revoke them and manage users.
// Login = password + TOTP. Listens on localhost; put Caddy/nginx (TLS) in front.
// The page is a static Vue app that talks to the JSON API under /api.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	_ "modernc.org/sqlite"
)

const (
	sessionTTL = 12 * time.Hour
	maxDays    = 30
)

var (
	db           *sql.DB
	signer       ssh.Signer
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("unused"), 12)
)

const schema = `
CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, pw_hash BLOB NOT NULL, totp_secret BLOB NOT NULL, principals TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT 0, admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS certs (serial INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, identity TEXT NOT NULL, pubkey TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);`

func main() {
	dbPath := flag.String("db", "/var/lib/ssh-ca-web/ca.db", "sqlite path")
	caKey := flag.String("ca", "/etc/ssh-ca/user_ca", "CA private key")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	db = openDB(*dbPath)

	if flag.Arg(0) == "adduser" {
		addUser(flag.Arg(1), flag.Arg(2))
		return
	}

	signer = loadCA(*caKey)
	http.HandleFunc("GET /{$}", static("text/html", indexHTML))
	http.HandleFunc("GET /app.js", static("text/javascript", appJS))
	http.HandleFunc("POST /api/login", login)
	http.HandleFunc("POST /api/logout", logout)
	http.HandleFunc("GET /api/me", authed(me))
	http.HandleFunc("GET /api/certs", authed(listCerts))
	http.HandleFunc("POST /api/certs", authed(sign))
	http.HandleFunc("POST /api/certs/{serial}/revoke", authed(revoke))
	http.HandleFunc("GET /api/users", adminOnly(listUsers))
	http.HandleFunc("POST /api/users", adminOnly(createUser))
	http.HandleFunc("DELETE /api/users/{name}", adminOnly(deleteUser))
	http.HandleFunc("GET /revoked_keys", revokedKeys) // public: servers cron-fetch this
	srv := &http.Server{
		Addr:              *addr,
		Handler:           secureHeaders(http.NewCrossOriginProtection().Handler(http.DefaultServeMux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Printf("listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

func openDB(path string) *sql.DB {
	d, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	check(err)
	d.SetMaxOpenConns(1) // ponytail: single writer, plenty for a handful of users
	_, err = d.Exec(schema)
	check(err)
	// Databases from before user management lack the admin column. Their users were all
	// created with adduser on the box, which makes admins, so they all become admins.
	if _, err := d.Exec(`ALTER TABLE users ADD COLUMN admin INTEGER NOT NULL DEFAULT 0`); err == nil {
		_, err = d.Exec(`UPDATE users SET admin=1`)
		check(err)
	}
	return d
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// CA passphrase comes from $CA_PASSPHRASE_FILE (systemd LoadCredential) or the terminal.
func loadCA(path string) ssh.Signer {
	raw, err := os.ReadFile(path)
	check(err)
	if s, err := ssh.ParsePrivateKey(raw); err == nil {
		return s
	}
	var pass []byte
	if f := os.Getenv("CA_PASSPHRASE_FILE"); f != "" {
		pass, err = os.ReadFile(f)
		check(err)
		pass = []byte(strings.TrimRight(string(pass), "\r\n"))
	} else {
		fmt.Fprint(os.Stderr, "CA passphrase: ")
		pass, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		check(err)
	}
	s, err := ssh.ParsePrivateKeyWithPassphrase(raw, pass)
	check(err)
	return s
}

// addUser creates or resets an admin from the command line. Anyone who can run it is
// root on the CA box already, so it is also the way back in if every admin is locked out.
func addUser(name, principals string) {
	if name == "" || principals == "" {
		log.Fatal("usage: ssh-ca-web adduser NAME root,hope")
	}
	check(validUser(name, principals))
	fmt.Fprint(os.Stderr, "password (12+ chars): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	check(err)
	if len(pw) < 12 {
		log.Fatal("password too short")
	}
	key, err := enrol(insertUser+` ON CONFLICT(name) DO UPDATE SET pw_hash=excluded.pw_hash,
		totp_secret=excluded.totp_secret, principals=excluded.principals, admin=1, last_totp=0`,
		name, principals, true, pw)
	check(err)
	// Only the link goes to stdout, so `adduser ... | qrencode -t ansiutf8` encodes nothing else.
	fmt.Fprintln(os.Stderr, "Add this link to your authenticator (or pipe stdout to `qrencode -t ansiutf8`):")
	fmt.Println(key.URL())
}

const insertUser = `INSERT INTO users(name,pw_hash,totp_secret,principals,admin) VALUES(?,?,?,?,?)`

// enrol stores a user with a fresh TOTP secret, using query (insertUser, or an upsert
// built on it), and returns the key for the user's authenticator app.
func enrol(query, name, principals string, admin bool, pw []byte) (*otp.Key, error) {
	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "ssh-ca", AccountName: name, Secret: secret})
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(query, name, hash, secret, principals, admin)
	return key, err
}

var (
	userRe      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	principalRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`) // a Linux username
)

func validUser(name, principals string) error {
	if !userRe.MatchString(name) {
		return errors.New("Usernames are 1 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter")
	}
	ps := strings.Split(principals, ",")
	if len(ps) > 16 {
		return errors.New("At most 16 server usernames")
	}
	for _, p := range ps {
		if !principalRe.MatchString(p) {
			return fmt.Errorf("%q is not a valid server username", p)
		}
	}
	return nil
}

// --- TOTP (RFC 6238 via pquerna/otp: SHA1, 6 digits, 30s) ---

var otpOpts = hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// verifyTOTP allows ±1 step of clock drift and rejects reuse (counter must exceed last).
// It checks each step itself, because the library's TOTP validator doesn't say which one matched.
func verifyTOTP(secret []byte, code string, last uint64, now time.Time) (uint64, bool) {
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	c := uint64(now.Unix() / 30)
	for _, n := range []uint64{c - 1, c, c + 1} {
		if ok, _ := hotp.ValidateCustom(code, n, b32, otpOpts); ok && n > last {
			return n, true
		}
	}
	return 0, false
}

// --- login throttling: 5 failures per IP per 15 min ---

var (
	failMu sync.Mutex
	fails  = map[string][]time.Time{}
)

func clientIP(r *http.Request) string {
	// Only reachable via Cloudflare (tunnel or CF-only firewall), so its header is trustworthy.
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func throttled(ip string, failed bool) bool {
	failMu.Lock()
	defer failMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	recent := fails[ip][:0]
	for _, t := range fails[ip] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	if failed {
		recent = append(recent, time.Now())
	}
	if len(recent) == 0 {
		delete(fails, ip)
	} else {
		fails[ip] = recent
	}
	return len(recent) >= 5
}

// --- sessions ---

func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

type account struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

// currentUser joins on users, so removing a user ends their sessions immediately.
func currentUser(r *http.Request) (a account) {
	c, err := r.Cookie("__Host-session")
	if err != nil {
		return a
	}
	db.QueryRow(`SELECT u.name,u.admin FROM sessions s JOIN users u ON u.name=s.user WHERE s.token_hash=? AND s.expires>?`,
		hashToken(c.Value), time.Now().Unix()).Scan(&a.Name, &a.Admin)
	return a
}

type handler func(http.ResponseWriter, *http.Request, account)

func authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := currentUser(r)
		if a.Name == "" {
			jsonError(w, http.StatusUnauthorized, "Not logged in")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		h(w, r, a)
	}
}

func adminOnly(h handler) http.HandlerFunc {
	return authed(func(w http.ResponseWriter, r *http.Request, a account) {
		if !a.Admin {
			jsonError(w, http.StatusForbidden, "Only admins can manage users")
			return
		}
		h(w, r, a)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) bool { return json.NewDecoder(r.Body).Decode(v) == nil }

//go:embed index.html
var indexHTML []byte

//go:embed app.js
var appJS []byte

func static(typ string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", typ+"; charset=utf-8")
		w.Write(body)
	}
}

// The CDN files are pinned to exact paths here and to their hashes in index.html.
// Tailwind's browser build injects <style> tags, which is what needs 'unsafe-inline'.
// Vue compiles the page's template with Function(), which is what needs 'unsafe-eval'.
// That is only safe while index.html stays static: data must reach the page as JSON
// through {{ }}, never be written into the HTML, or it could be compiled as template code.
const csp = "default-src 'none'; img-src 'self' data:; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; " +
	"script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4.3.3/dist/index.global.js https://cdn.jsdelivr.net/npm/vue@3.5.43/dist/vue.global.prod.js; " +
	"style-src 'unsafe-inline' https://cdn.jsdelivr.net/npm/daisyui@5.7.46/daisyui.css"

func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if throttled(ip, false) {
		jsonError(w, http.StatusTooManyRequests, "Too many attempts. Try again in 15 minutes.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var in struct{ User, Password, Code string }
	readJSON(r, &in)
	name, pw, code := in.User, in.Password, in.Code

	var hash, secret []byte
	var last uint64
	err := db.QueryRow(`SELECT pw_hash,totp_secret,last_totp FROM users WHERE name=?`, name).Scan(&hash, &secret, &last)
	if err != nil {
		hash = dummyHash // equalise timing for unknown users
	}
	pwOK := bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
	step, codeOK := verifyTOTP(secret, code, last, time.Now())
	if err != nil || !pwOK || !codeOK {
		throttled(ip, true)
		// Only in the server's journal (root-only). Says which factor failed, so a
		// lockout is diagnosable without weakening what the browser is told.
		log.Printf("login failed user=%q ip=%s user_found=%t password_ok=%t code_ok=%t now_step=%d last_step=%d",
			name, ip, err == nil, pwOK, codeOK, time.Now().Unix()/30, last)
		jsonError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	db.Exec(`UPDATE users SET last_totp=? WHERE name=?`, step, name)

	tok := rand.Text()
	db.Exec(`DELETE FROM sessions WHERE expires<?`, time.Now().Unix())
	db.Exec(`INSERT INTO sessions VALUES(?,?,?)`, hashToken(tok), name, time.Now().Add(sessionTTL).Unix())
	http.SetCookie(w, &http.Cookie{Name: "__Host-session", Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	log.Printf("login ok user=%q ip=%s", name, ip)
	w.WriteHeader(http.StatusNoContent)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("__Host-session"); err == nil {
		db.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-session", Path: "/", Secure: true, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// --- API ---

func me(w http.ResponseWriter, r *http.Request, a account) {
	ca := signer.PublicKey()
	writeJSON(w, http.StatusOK, map[string]any{
		"name": a.Name, "admin": a.Admin, "maxDays": maxDays,
		"ca": map[string]string{
			"key":         strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca))),
			"type":        ca.Type(),
			"fingerprint": ssh.FingerprintSHA256(ca),
		},
	})
}

type certRow struct {
	Serial      int64     `json:"serial"`
	Identity    string    `json:"identity"`
	Pubkey      string    `json:"pubkey"`
	Fingerprint string    `json:"fingerprint"`
	Expires     time.Time `json:"expires"`
	Revoked     bool      `json:"revoked"`
	Expired     bool      `json:"expired"`
}

func listCerts(w http.ResponseWriter, r *http.Request, a account) {
	rows, err := db.Query(`SELECT serial,identity,pubkey,expires,revoked FROM certs WHERE user=? ORDER BY serial DESC LIMIT 200`, a.Name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	defer rows.Close()
	out := []certRow{}
	for rows.Next() {
		var c certRow
		var exp int64
		rows.Scan(&c.Serial, &c.Identity, &c.Pubkey, &exp, &c.Revoked)
		c.Expires = time.Unix(exp, 0)
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.Pubkey)); err == nil {
			c.Fingerprint = ssh.FingerprintSHA256(k)
		}
		c.Expired = time.Now().After(c.Expires)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func sign(w http.ResponseWriter, r *http.Request, a account) {
	fail := func(msg string) { jsonError(w, http.StatusBadRequest, msg) }
	var in struct {
		Identity, Pubkey string
		Days             int
	}
	if !readJSON(r, &in) {
		fail("Bad request")
		return
	}
	identity := strings.TrimSpace(in.Identity)
	if identity == "" || len(identity) > 64 || strings.ContainsAny(identity, "\r\n") {
		fail("Bad device name")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.Pubkey))
	if err != nil {
		fail("Not a valid public key")
		return
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		fail("Paste the plain public key, not a certificate")
		return
	}
	if pub.Type() == ssh.KeyAlgoRSA {
		if k, ok := pub.(ssh.CryptoPublicKey); ok {
			if rk, ok := k.CryptoPublicKey().(interface{ Size() int }); ok && rk.Size() < 384 {
				fail("RSA keys must be ≥3072 bits; prefer ed25519")
				return
			}
		}
	}
	keyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	var banned bool
	db.QueryRow(`SELECT 1 FROM certs WHERE pubkey=? AND revoked=1`, keyStr).Scan(&banned)
	if banned {
		fail("This key is revoked. Generate a new one.")
		return
	}
	days := min(max(in.Days, 1), maxDays)

	var principals string
	if err := db.QueryRow(`SELECT principals FROM users WHERE name=?`, a.Name).Scan(&principals); err != nil {
		fail("User lookup failed")
		return
	}
	now := time.Now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	res, err := db.Exec(`INSERT INTO certs(user,identity,pubkey,expires) VALUES(?,?,?,?)`, a.Name, identity, keyStr, expires.Unix())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	serial, _ := res.LastInsertId()

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          uint64(serial),
		CertType:        ssh.UserCert,
		KeyId:           a.Name + ":" + identity,
		ValidPrincipals: strings.Split(principals, ","),
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(expires.Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty": "", "permit-port-forwarding": "", "permit-agent-forwarding": "", "permit-user-rc": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		db.Exec(`DELETE FROM certs WHERE serial=?`, serial)
		jsonError(w, http.StatusInternalServerError, "Signing failed")
		return
	}
	log.Printf("signed serial=%d user=%q id=%q days=%d", serial, a.Name, identity, days)
	writeJSON(w, http.StatusOK, map[string]any{
		"serial": serial, "file": certFile(pub.Type()), "cert": string(ssh.MarshalAuthorizedKey(cert)),
	})
}

// certFile is where ssh looks for the certificate of a default-named key of this type.
func certFile(keyType string) string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return "id_rsa-cert.pub"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "id_ecdsa-cert.pub"
	case ssh.KeyAlgoSKED25519:
		return "id_ed25519_sk-cert.pub"
	case ssh.KeyAlgoSKECDSA256:
		return "id_ecdsa_sk-cert.pub"
	}
	return "id_ed25519-cert.pub"
}

// revoke bans the underlying public key, so every cert ever issued for it dies.
func revoke(w http.ResponseWriter, r *http.Request, a account) {
	serial, _ := strconv.ParseInt(r.PathValue("serial"), 10, 64)
	res, err := db.Exec(`UPDATE certs SET revoked=1 WHERE pubkey=(SELECT pubkey FROM certs WHERE serial=? AND user=?)`, serial, a.Name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		jsonError(w, http.StatusNotFound, "No such certificate")
		return
	}
	log.Printf("revoked serial=%d user=%q", serial, a.Name)
	w.WriteHeader(http.StatusNoContent)
}

// --- users (admins only) ---

type userRow struct {
	Name       string   `json:"name"`
	Principals []string `json:"principals"`
	Admin      bool     `json:"admin"`
	Active     int      `json:"active"` // unexpired, unrevoked certificates
}

func listUsers(w http.ResponseWriter, r *http.Request, a account) {
	rows, err := db.Query(`SELECT name,principals,admin,
		(SELECT COUNT(*) FROM certs c WHERE c.user=u.name AND revoked=0 AND expires>?) FROM users u ORDER BY name`, time.Now().Unix())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	defer rows.Close()
	out := []userRow{}
	for rows.Next() {
		var u userRow
		var ps string
		rows.Scan(&u.Name, &ps, &u.Admin, &u.Active)
		u.Principals = strings.Split(ps, ",")
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// createUser generates the password as well as the TOTP secret, so no new account
// starts with a weak password. The admin sees both once and passes them on.
func createUser(w http.ResponseWriter, r *http.Request, a account) {
	var in struct {
		Name, Principals string
		Admin            bool
	}
	if !readJSON(r, &in) {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return
	}
	in.Principals = strings.ReplaceAll(in.Principals, " ", "")
	if err := validUser(in.Name, in.Principals); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	pw := rand.Text()
	key, err := enrol(insertUser, in.Name, in.Principals, in.Admin, []byte(pw))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonError(w, http.StatusConflict, "That username is taken")
		} else {
			jsonError(w, http.StatusInternalServerError, "DB error")
		}
		return
	}
	log.Printf("user created name=%q admin=%t principals=%q by=%q", in.Name, in.Admin, in.Principals, a.Name)
	writeJSON(w, http.StatusCreated, map[string]string{
		"name": in.Name, "password": pw, "secret": key.Secret(), "url": key.URL(),
	})
}

// deleteUser also revokes every key the user ever had signed. Otherwise their
// certificates would keep working on the servers for up to maxDays.
func deleteUser(w http.ResponseWriter, r *http.Request, a account) {
	name := r.PathValue("name")
	if name == a.Name {
		jsonError(w, http.StatusBadRequest, "You can't remove yourself")
		return
	}
	tx, err := db.Begin()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM users WHERE name=?`, name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		jsonError(w, http.StatusNotFound, "No such user")
		return
	}
	_, err1 := tx.Exec(`UPDATE certs SET revoked=1 WHERE pubkey IN (SELECT pubkey FROM certs WHERE user=?)`, name)
	_, err2 := tx.Exec(`DELETE FROM sessions WHERE user=?`, name)
	if err := errors.Join(err1, err2, tx.Commit()); err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	log.Printf("user removed name=%q by=%q", name, a.Name)
	w.WriteHeader(http.StatusNoContent)
}

// revokedKeys serves an OpenSSH RevokedKeys file (one public key per line).
func revokedKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT DISTINCT pubkey FROM certs WHERE revoked=1`)
	if err != nil {
		http.Error(w, "db error", 500) // non-200 so the server-side cron keeps its old file
		return
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			keys = append(keys, k)
		}
	}
	// A half-read list must not pass for a whole one: a truncated ban list would let
	// revoked keys back in, so fail the request instead and let the cron keep its file.
	if rows.Err() != nil {
		http.Error(w, "db error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	for _, k := range keys {
		fmt.Fprintln(w, k)
	}
}
