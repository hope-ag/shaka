// Accounts: the adduser command, enrolment, validation, and the admin-only API.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const insertUser = `INSERT INTO users(name,pw_hash,totp_secret,principals,admin) VALUES(?,?,?,?,?)`

var (
	userRe      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	principalRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`) // a Linux username
)

func validUser(name, principals string) error {
	if !userRe.MatchString(name) {
		return errors.New("Usernames are 1 to 32 lowercase letters, digits, dots, dashes or underscores, starting with a letter")
	}
	return validPrincipals(principals)
}

// validPrincipals checks the list of Linux usernames a certificate will allow, which
// createUser, editUser and adduser all pass in the same comma-separated form.
func validPrincipals(principals string) error {
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

// enrol stores a user with a fresh TOTP secret, using query (insertUser, or an upsert
// built on it), and returns the key for the user's authenticator app.
func enrol(query, name, principals string, admin bool, pw []byte) (*otp.Key, error) {
	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "shaka", AccountName: name, Secret: secret})
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(query, name, hash, secret, principals, admin)
	return key, err
}

// addUser creates or resets an admin from the command line. admin.sh runs it on a
// copy of the database, needing access to the bucket, so it is also the way back in if every admin is locked out.
func addUser(name, principals string) {
	if name == "" || principals == "" {
		log.Fatal("usage: shaka adduser NAME root,NAME")
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

// editUser changes an account's server usernames and whether it is an admin, leaving
// the password, the authenticator secret and any open sessions alone. The certificates
// someone already holds are untouched too: the usernames they allow were written into
// the certificate when it was signed, so a username taken away here stops appearing in
// the next one, and revoking is still the way to end the old ones early.
func editUser(w http.ResponseWriter, r *http.Request, a account) {
	name := r.PathValue("name")
	var in struct {
		Principals string
		Admin      bool
	}
	if !readJSON(r, &in) {
		jsonError(w, http.StatusBadRequest, "Bad request")
		return
	}
	in.Principals = strings.ReplaceAll(in.Principals, " ", "")
	if err := validPrincipals(in.Principals); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Same idea as not being able to remove yourself: an admin who drops their own
	// admin flag loses the Users page. admin.sh is still the way back in.
	if name == a.Name && !in.Admin {
		jsonError(w, http.StatusBadRequest, "You can't drop your own admin access")
		return
	}
	// SQLite counts every row the WHERE clause matched, so saving without changing
	// anything still reports a row and does not look like a missing user.
	res, err := db.Exec(`UPDATE users SET principals=?,admin=? WHERE name=?`, in.Principals, in.Admin, name)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "DB error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		jsonError(w, http.StatusNotFound, "No such user")
		return
	}
	log.Printf("user edited name=%q admin=%t principals=%q by=%q", name, in.Admin, in.Principals, a.Name)
	w.WriteHeader(http.StatusNoContent)
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
