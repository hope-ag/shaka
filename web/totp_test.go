package main

import (
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	secret := []byte("12345678901234567890") // RFC 6238 test vector
	if got := totp(secret, 59/30); got != "287082" {
		t.Fatalf("got %s", got)
	}
	now := time.Unix(59, 0)
	step, ok := verifyTOTP(secret, "287082", 0, now)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := verifyTOTP(secret, "287082", step, now); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := verifyTOTP(secret, "000000", 0, now); ok {
		t.Fatal("wrong code accepted")
	}
}
