// Logging in, sessions, and the per-address throttle on failed attempts.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 12 * time.Hour

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("unused"), 12)

// --- login throttling: 5 failures per IP per 15 min ---

var (
	failMu sync.Mutex
	fails  = map[string][]time.Time{}
)

func clientIP(r *http.Request) string {
	// Cloud Run's front end appends the address it saw to X-Forwarded-For, so only the last
	// entry is trustworthy; anything before it came from the client and could be made up.
	if v := strings.Join(r.Header.Values("X-Forwarded-For"), ","); v != "" {
		if ip := net.ParseIP(strings.TrimSpace(v[strings.LastIndex(v, ",")+1:])); ip != nil {
			return ip.String()
		}
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
		// Only in the Cloud Run logs, which need project access. Says which factor failed, so a
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
