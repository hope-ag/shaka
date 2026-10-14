// The CA key, signing device keys, revoking them, and the ban list servers fetch.
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const maxDays = 30

var signer ssh.Signer

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
