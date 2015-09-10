package onepassword

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKeys derives the encryption and MAC keys that are used decrypt and
// authenticate the master encryption and MAC keys.
func DeriveKeys(pass string, salt []byte, nIters int) ([]byte, []byte) {
	data := pbkdf2.Key([]byte(pass), salt, nIters, 64, sha512.New)
	return data[0:32], data[32:64]
}
