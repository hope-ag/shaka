// ssh-ca-web: tiny web UI to sign device keys and revoke them.
// Login = password + TOTP. Listens on localhost; put Caddy/nginx (TLS) in front.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, pw_hash BLOB NOT NULL, totp_secret BLOB NOT NULL, principals TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS certs (serial INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, identity TEXT NOT NULL, pubkey TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);`

func main() {
	dbPath := flag.String("db", "/var/lib/ssh-ca-web/ca.db", "sqlite path")
	caKey := flag.String("ca", "/etc/ssh-ca/user_ca", "CA private key")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	var err error
	db, err = sql.Open("sqlite", *dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	check(err)
	db.SetMaxOpenConns(1) // ponytail: single writer, plenty for a handful of users
	_, err = db.Exec(schema)
	check(err)

	if flag.Arg(0) == "adduser" {
		addUser(flag.Arg(1), flag.Arg(2))
		return
	}

	signer = loadCA(*caKey)
	http.HandleFunc("GET /{$}", index)
	http.HandleFunc("POST /login", login)
	http.HandleFunc("POST /logout", logout)
	http.HandleFunc("POST /sign", authed(sign))
	http.HandleFunc("POST /revoke", authed(revoke))
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

func addUser(name, principals string) {
	if name == "" || principals == "" {
		log.Fatal("usage: ssh-ca-web adduser NAME root,hope")
	}
	fmt.Fprint(os.Stderr, "password (12+ chars): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	check(err)
	if len(pw) < 12 {
		log.Fatal("password too short")
	}
	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	check(err)
	secret := make([]byte, 20)
	rand.Read(secret)
	_, err = db.Exec(`INSERT INTO users(name,pw_hash,totp_secret,principals) VALUES(?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET pw_hash=excluded.pw_hash, totp_secret=excluded.totp_secret, principals=excluded.principals, last_totp=0`,
		name, hash, secret, principals)
	check(err)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	fmt.Printf("Add to your authenticator (or pipe to `qrencode -t ansiutf8`):\notpauth://totp/ssh-ca:%s?secret=%s&issuer=ssh-ca\n", name, b32)
}

// --- TOTP (RFC 6238, SHA1, 6 digits, 30s) ---

func totp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h := hmac.New(sha1.New, secret)
	h.Write(buf[:])
	sum := h.Sum(nil)
	o := sum[len(sum)-1] & 0xf
	code := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000)
}

// verifyTOTP allows ±1 step of clock drift and rejects reuse (counter must exceed last).
func verifyTOTP(secret []byte, code string, last uint64, now time.Time) (uint64, bool) {
	c := uint64(now.Unix() / 30)
	for _, n := range []uint64{c - 1, c, c + 1} {
		if n > last && subtle.ConstantTimeCompare([]byte(totp(secret, n)), []byte(code)) == 1 {
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

func currentUser(r *http.Request) string {
	c, err := r.Cookie("__Host-session")
	if err != nil {
		return ""
	}
	var user string
	db.QueryRow(`SELECT user FROM sessions WHERE token_hash=? AND expires>?`, hashToken(c.Value), time.Now().Unix()).Scan(&user)
	return user
}

func authed(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if u == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		h(w, r, u)
	}
}

func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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
		http.Error(w, "too many attempts, try later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	name, pw, code := r.FormValue("user"), r.FormValue("password"), r.FormValue("code")

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
		log.Printf("login failed user=%q ip=%s", name, ip)
		render(w, page{Error: "Invalid credentials"})
		return
	}
	db.Exec(`UPDATE users SET last_totp=? WHERE name=?`, step, name)

	tok := rand.Text()
	db.Exec(`DELETE FROM sessions WHERE expires<?`, time.Now().Unix())
	db.Exec(`INSERT INTO sessions VALUES(?,?,?)`, hashToken(tok), name, time.Now().Add(sessionTTL).Unix())
	http.SetCookie(w, &http.Cookie{Name: "__Host-session", Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	log.Printf("login ok user=%q ip=%s", name, ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("__Host-session"); err == nil {
		db.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-session", Path: "/", Secure: true, MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- pages ---

type certRow struct {
	Serial           int64
	Identity, Pubkey string
	Expires          time.Time
	Revoked, Expired bool
}

type page struct {
	User, Error, Cert string
	Certs             []certRow
}

var tmpl = template.Must(template.New("").Parse(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>SSH CA</title><style>body{font:15px system-ui;max-width:52rem;margin:2rem auto;padding:0 1rem}textarea,input{width:100%;box-sizing:border-box;margin:.25rem 0 .75rem;font:13px monospace}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:.3rem;border-bottom:1px solid #ccc;font-size:13px}.err{color:#b00}.dim{opacity:.5}button{padding:.4rem 1rem}</style>
<h1>SSH CA</h1>
{{if .Error}}<p class=err>{{.Error}}</p>{{end}}
{{if not .User}}
<form method=post action=/login>
<label>User<input name=user autocomplete=username required></label>
<label>Password<input name=password type=password autocomplete=current-password required></label>
<label>Authenticator code<input name=code inputmode=numeric pattern="[0-9]{6}" autocomplete=one-time-code required></label>
<button>Log in</button></form>
{{else}}
<form method=post action=/logout style="float:right;margin-top:-3.5rem"><button>Log out {{.User}}</button></form>
{{if .Cert}}<h2>Certificate</h2><p>Save as <code>~/.ssh/id_ed25519-cert.pub</code>:</p><textarea rows=6 readonly>{{.Cert}}</textarea>{{end}}
<h2>Sign a key</h2>
<form method=post action=/sign>
<label>Device name<input name=identity required maxlength=64 placeholder="hope-laptop-2026"></label>
<label>Public key (id_ed25519.pub)<textarea name=pubkey rows=3 required></textarea></label>
<label>Valid for (days, max ` + strconv.Itoa(maxDays) + `)<input name=days type=number min=1 max=` + strconv.Itoa(maxDays) + ` value=7></label>
<button>Sign</button></form>
<h2>Issued</h2>
<table><tr><th>#<th>Device<th>Key<th>Expires<th></tr>
{{range .Certs}}<tr class="{{if or .Revoked .Expired}}dim{{end}}"><td>{{.Serial}}<td>{{.Identity}}<td title="{{.Pubkey}}">{{slice .Pubkey 0 24}}…<td>{{.Expires.Format "2006-01-02 15:04"}}
<td>{{if .Revoked}}revoked{{else}}<form method=post action=/revoke><input type=hidden name=serial value={{.Serial}}><button>Revoke key</button></form>{{end}}</tr>{{end}}
</table>{{end}}`))

func render(w http.ResponseWriter, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, p); err != nil {
		log.Print(err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	render(w, page{User: currentUser(r), Certs: listCerts(currentUser(r))})
}

func listCerts(user string) []certRow {
	if user == "" {
		return nil
	}
	rows, err := db.Query(`SELECT serial,identity,pubkey,expires,revoked FROM certs WHERE user=? ORDER BY serial DESC LIMIT 200`, user)
	if err != nil {
		log.Print(err)
		return nil
	}
	defer rows.Close()
	var out []certRow
	for rows.Next() {
		var c certRow
		var exp int64
		rows.Scan(&c.Serial, &c.Identity, &c.Pubkey, &exp, &c.Revoked)
		c.Expires = time.Unix(exp, 0)
		c.Expired = time.Now().After(c.Expires)
		out = append(out, c)
	}
	return out
}

func sign(w http.ResponseWriter, r *http.Request, user string) {
	fail := func(msg string) { render(w, page{User: user, Error: msg, Certs: listCerts(user)}) }

	identity := strings.TrimSpace(r.FormValue("identity"))
	if identity == "" || len(identity) > 64 || strings.ContainsAny(identity, "\r\n") {
		fail("Bad device name")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.FormValue("pubkey")))
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
	days, _ := strconv.Atoi(r.FormValue("days"))
	days = min(max(days, 1), maxDays)

	var principals string
	if err := db.QueryRow(`SELECT principals FROM users WHERE name=?`, user).Scan(&principals); err != nil {
		fail("User lookup failed")
		return
	}
	now := time.Now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	res, err := db.Exec(`INSERT INTO certs(user,identity,pubkey,expires) VALUES(?,?,?,?)`, user, identity, keyStr, expires.Unix())
	if err != nil {
		fail("DB error")
		return
	}
	serial, _ := res.LastInsertId()

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          uint64(serial),
		CertType:        ssh.UserCert,
		KeyId:           user + ":" + identity,
		ValidPrincipals: strings.Split(principals, ","),
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(expires.Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty": "", "permit-port-forwarding": "", "permit-agent-forwarding": "", "permit-user-rc": "",
		}},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		db.Exec(`DELETE FROM certs WHERE serial=?`, serial)
		fail("Signing failed")
		return
	}
	log.Printf("signed serial=%d user=%q id=%q days=%d", serial, user, identity, days)
	render(w, page{User: user, Cert: string(ssh.MarshalAuthorizedKey(cert)), Certs: listCerts(user)})
}

// revoke bans the underlying public key, so every cert ever issued for it dies.
func revoke(w http.ResponseWriter, r *http.Request, user string) {
	serial, _ := strconv.ParseInt(r.FormValue("serial"), 10, 64)
	res, _ := db.Exec(`UPDATE certs SET revoked=1 WHERE pubkey=(SELECT pubkey FROM certs WHERE serial=? AND user=?)`, serial, user)
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("revoked serial=%d user=%q", serial, user)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// revokedKeys serves an OpenSSH RevokedKeys file (one public key per line).
func revokedKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`SELECT DISTINCT pubkey FROM certs WHERE revoked=1`)
	if err != nil {
		http.Error(w, "db error", 500) // non-200 so the server-side cron keeps its old file
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/plain")
	for rows.Next() {
		var k string
		rows.Scan(&k)
		fmt.Fprintln(w, k)
	}
}
