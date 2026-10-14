package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// call runs h as the user whose session token is tok and returns the status code.
func call(h http.HandlerFunc, method, path, body, tok string, pathValues ...string) int {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: tok})
	for i := 0; i+1 < len(pathValues); i += 2 {
		r.SetPathValue(pathValues[i], pathValues[i+1])
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w.Code
}

func TestUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.db")

	// A database from before the admin column: its user must come out as an admin.
	old, _ := sql.Open("sqlite", path)
	if _, err := old.Exec(`CREATE TABLE users (name TEXT PRIMARY KEY, pw_hash BLOB NOT NULL, totp_secret BLOB NOT NULL, principals TEXT NOT NULL, last_totp INTEGER NOT NULL DEFAULT 0);
		INSERT INTO users(name,pw_hash,totp_secret,principals) VALUES('ann','x','x','root,ann')`); err != nil {
		t.Fatal(err)
	}
	old.Close()
	db = openDB(path)
	t.Cleanup(func() { db.Close() })

	if _, err := enrol(insertUser, "bob", "bob", false, []byte("password1234")); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	db.Exec(`INSERT INTO sessions VALUES(?,?,?),(?,?,?)`, hashToken("ann-tok"), "ann", exp, hashToken("bob-tok"), "bob", exp)
	db.Exec(`INSERT INTO certs(user,identity,pubkey,expires) VALUES('bob','phone','ssh-ed25519 BOBKEY',?)`, exp)

	list, create, del := adminOnly(listUsers), adminOnly(createUser), adminOnly(deleteUser)
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"migrated admin lists users", call(list, "GET", "/", "", "ann-tok"), 200},
		{"non-admin can't list", call(list, "GET", "/", "", "bob-tok"), 403},
		{"no session", call(list, "GET", "/", "", "nope"), 401},
		{"create", call(create, "POST", "/", `{"name":"cat","principals":"cat, deploy"}`, "ann-tok"), 201},
		{"duplicate name", call(create, "POST", "/", `{"name":"cat","principals":"cat"}`, "ann-tok"), 409},
		{"bad name", call(create, "POST", "/", `{"name":"Cat!","principals":"cat"}`, "ann-tok"), 400},
		{"bad principal", call(create, "POST", "/", `{"name":"dan","principals":"root;rm"}`, "ann-tok"), 400},
		{"non-admin can't delete", call(del, "DELETE", "/", "", "bob-tok", "name", "ann"), 403},
		{"can't delete self", call(del, "DELETE", "/", "", "ann-tok", "name", "ann"), 400},
		{"delete", call(del, "DELETE", "/", "", "ann-tok", "name", "bob"), 204},
		{"deleted user's session is dead", call(list, "GET", "/", "", "bob-tok"), 401},
		{"delete missing", call(del, "DELETE", "/", "", "ann-tok", "name", "bob"), 404},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}

	// createUser strips the spaces, so what is stored is the bare list.
	var principals string
	db.QueryRow(`SELECT principals FROM users WHERE name='cat'`).Scan(&principals)
	if principals != "cat,deploy" {
		t.Errorf("principals stored as %q", principals)
	}
	var revoked bool
	db.QueryRow(`SELECT revoked FROM certs WHERE user='bob'`).Scan(&revoked)
	if !revoked {
		t.Error("removed user's key was not revoked")
	}

	// --- editing an account ---

	// cat was created by the table above: principals "cat,deploy", not an admin.
	db.Exec(`INSERT INTO sessions VALUES(?,?,?)`, hashToken("cat-tok"), "cat", exp)
	var pwBefore, secBefore []byte
	db.QueryRow(`SELECT pw_hash,totp_secret FROM users WHERE name='cat'`).Scan(&pwBefore, &secBefore)

	edit := adminOnly(editUser)
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"non-admin can't edit", call(edit, "PUT", "/", `{"principals":"cat"}`, "cat-tok", "name", "ann"), 403},
		{"no session can't edit", call(edit, "PUT", "/", `{"principals":"cat"}`, "nope", "name", "cat"), 401},
		{"bad principal", call(edit, "PUT", "/", `{"principals":"cat;rm"}`, "ann-tok", "name", "cat"), 400},
		{"can't drop own admin", call(edit, "PUT", "/", `{"principals":"root,ann","admin":false}`, "ann-tok", "name", "ann"), 400},
		{"edit missing user", call(edit, "PUT", "/", `{"principals":"cat"}`, "ann-tok", "name", "nobody"), 404},
		{"edit", call(edit, "PUT", "/", `{"principals":"cat, web","admin":true}`, "ann-tok", "name", "cat"), 204},
		{"edited user keeps their session", call(list, "GET", "/", "", "cat-tok"), 200},
		{"saving the same thing again", call(edit, "PUT", "/", `{"principals":"cat,web","admin":true}`, "ann-tok", "name", "cat"), 204},
	} {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}

	db.QueryRow(`SELECT principals FROM users WHERE name='cat'`).Scan(&principals)
	if principals != "cat,web" {
		t.Errorf("edited principals stored as %q", principals)
	}
	var pwAfter, secAfter []byte
	db.QueryRow(`SELECT pw_hash,totp_secret FROM users WHERE name='cat'`).Scan(&pwAfter, &secAfter)
	if !bytes.Equal(pwBefore, pwAfter) || !bytes.Equal(secBefore, secAfter) {
		t.Error("editing an account changed its password or authenticator secret")
	}
	var admin bool
	db.QueryRow(`SELECT admin FROM users WHERE name='ann'`).Scan(&admin)
	if !admin {
		t.Error("an admin dropped their own access")
	}
}
