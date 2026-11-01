package main

import (
	"net/http/httptest"
	"testing"
)

// Only the entry Cloud Run appended counts; a client-supplied one must not dodge the throttle.
func TestClientIP(t *testing.T) {
	for _, c := range []struct {
		xff  []string
		want string
	}{
		{nil, "192.0.2.1"},
		{[]string{"203.0.113.9"}, "203.0.113.9"},
		{[]string{"9.9.9.9, 203.0.113.9"}, "203.0.113.9"},
		{[]string{"9.9.9.9", "8.8.8.8,203.0.113.9"}, "203.0.113.9"},
		{[]string{"9.9.9.9,"}, "192.0.2.1"},
	} {
		r := httptest.NewRequest("POST", "/api/login", nil)
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("X-Forwarded-For %q: got %q, want %q", c.xff, got, c.want)
		}
	}
}
