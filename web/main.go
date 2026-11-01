// shaka: tiny web UI to sign device keys, revoke them and manage users.
// Login = password + TOTP. Runs on Cloud Run behind Litestream (see Dockerfile).
// The page is a static Vue app that talks to the JSON API under /api.
//
// The package is split by area: auth.go is logging in and sessions, users.go is
// accounts, certs.go is the CA and the certificates it signs, totp.go is the
// authenticator codes, and this file starts the server and holds the plumbing.
package main

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

const schema = `
CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, pw_hash BLOB NOT NULL, totp_secret BLOB NOT NULL, principals TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT 0, admin INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS certs (serial INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, identity TEXT NOT NULL, pubkey TEXT NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);`

func main() {
	dbPath := flag.String("db", "/data/ca.db", "sqlite path")
	caKey := flag.String("ca", "/secrets/key/user_ca", "CA private key")
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
	http.HandleFunc("PUT /api/users/{name}", adminOnly(editUser))
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
