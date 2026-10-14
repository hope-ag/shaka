package main

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	secret := []byte("12345678901234567890") // RFC 6238 test vector
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

// All SHA-1 vectors from RFC 6238 Appendix B. They are 8 digits; a 6-digit code is the last six.
func TestTOTPRFCVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		if _, ok := verifyTOTP(secret, want[2:], 0, time.Unix(unix, 0)); !ok {
			t.Errorf("t=%d: %s rejected", unix, want[2:])
		}
	}
}

// A secret written the way an enrolment prints it, base32 without padding, must decode
// to the bytes whose code an independent implementation (Python hmac) computed for
// 21:31:30 UTC. The secret is made up: a real one must never appear in the tests.
func TestTOTPFromOtpauthSecret(t *testing.T) {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("ONZWQLLDMEQHIZLTOQQHMZLDORXXEIJB")
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{-30, 0, 29, 59} { // previous, same and next step all verify
		if _, ok := verifyTOTP(secret, "311313", 0, time.Unix(1791927090+off, 0)); !ok {
			t.Errorf("offset %ds: valid code rejected", off)
		}
	}
}
