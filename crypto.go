package onepassword

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

// ComputeDerivedKeys derives the encryption and MAC keys that are used decrypt and
// authenticate the master encryption and MAC keys.
func ComputeDerivedKeys(pass string, salt []byte, nIters int) (encKey, macKey []byte) {
	data := pbkdf2.Key([]byte(pass), salt, nIters, 64, sha512.New)
	return data[0:32], data[32:64]
}

// ComputeMasterKeys produces the master encryption and MAC keys given the
// master key.
func ComputeMasterKeys(masterKey []byte) (encKey, macKey []byte) {
	data := sha512.Sum512(masterKey)
	return data[0:32], data[32:64]
}
