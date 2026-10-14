// TOTP (RFC 6238 via pquerna/otp: SHA1, 6 digits, 30s).
package main

import (
	"encoding/base32"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)

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
