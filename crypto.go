package onepassword

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/pbkdf2"
)

const (
	EncKeySize = 32
	MACKeySize = 32
)

var (
	ErrIncompleteHeader     = errors.New("incomplete header")
	ErrIncompleteCiphertext = errors.New("incomplete ciphertext")
	ErrIncompleteIV         = errors.New("incomplete IV")
	ErrIncompleteMagic      = errors.New("incomplete magic")
	ErrIncompleteMAC        = errors.New("incomplete MAC")
	ErrIncorrectMAC         = errors.New("incorrect MAC")
	ErrInvalidMagic         = errors.New("invalid magic")

	OPData01Magic           = []byte("opdata01")
)

// KeyPair holds an encryption and MAC key used to store data in the vault.
type KeyPair struct {
	EncKey []byte
	MACKey []byte
}

// ComputeDerivedKeys derives the encryption and MAC keys that are used decrypt and
// authenticate the master encryption and MAC keys.
func ComputeDerivedKeys(pass string, salt []byte, nIters int) (*KeyPair) {
	data := pbkdf2.Key([]byte(pass), salt, nIters, 64, sha512.New)
	return &KeyPair{data[0:32], data[32:64]}
}

// DecryptMasterKeys returns a "master" keypair given opdata. Use this to decode
// both the master item keys and master overview keys.
func DecryptMasterKeys(opdata []byte, derivedKeys *KeyPair) (*KeyPair, error) {
	mkData, err := DecryptOPData01(opdata, derivedKeys)
	if err != nil {
		return nil, err
	}
	data := sha512.Sum512(mkData)
	return &KeyPair{data[0:32], data[32:64]}, nil
}

// authenticate verifies the mac on the supplied blob. The supplied blob is
// expected to be in the format data + MAC. On success, authenticate returns
// a new slice containing only the verified data.
func authenticate(blob []byte, kp *KeyPair) ([]byte, error) {
	if len(blob) < sha256.Size {
		return nil, ErrIncompleteMAC
	}

	macOff := len(blob) - sha256.Size
	data := blob[0:macOff]
	dataMAC := blob[macOff: len(blob)]
	mac := hmac.New(sha256.New, kp.MACKey)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(dataMAC, expectedMAC) {
		return nil, ErrIncorrectMAC
	}

	return data, nil
}

// decrypt decrypts the supplied blob. The blob is expected to be in the format
// IV + ciphertext.
func decrypt(blob []byte, kp *KeyPair) ([]byte, error) {
	r := bytes.NewReader(blob)

	// Read IV
	iv := make([]byte, aes.BlockSize)
	n, err := r.Read(iv)
	if err != nil {
		return nil, err
	} else if n != aes.BlockSize {
		return nil, ErrIncompleteIV
	}

	// Read ciphertext
	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	} else if len(ciphertext) < aes.BlockSize {
		return nil, ErrIncompleteCiphertext
	}

	// Decrypt
	b, err := aes.NewCipher(kp.EncKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(b, iv)
	bm.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// DecryptOPData01 parses, authenticates, and decrypts OPData01 blobs. The
// OPData01 format is:
//     8  bytes - "opdata01"
//     8  bytes - plaintext length, uint64_t, little endian
//     16 bytes - IV
//     variable - ciphertext
//     32 bytes - MAC
func DecryptOPData01(opdata []byte, kp *KeyPair) ([]byte, error) {
	opdata, err := authenticate(opdata, kp)
	if err != nil {
		return nil, err
	}

	r := bytes.NewBuffer(opdata)

	// Read magic
	magic := make([]byte, len(OPData01Magic))
	n, err := r.Read(magic)
	if err != nil {
		return nil, err
	} else if n != len(magic) {
		return nil, ErrIncompleteMagic
	} else if !bytes.Equal(magic, OPData01Magic) {
		return nil, ErrInvalidMagic
	}

	// Read plaintext length
	var ptLen uint64
	err = binary.Read(r, binary.LittleEndian, &ptLen)
	if err != nil {
		return nil, err
	}
	padLen := aes.BlockSize - (ptLen % aes.BlockSize)

	// Decrypt data
	ct, err := ioutil.ReadAll(r)
	plaintext, err := decrypt(ct, kp)
	if err != nil {
		return nil, err
	}

	return plaintext[padLen:len(plaintext)], nil
}

// DecryptItemKey parses, authenticates, and decrypts item key blobs. Item Key
// blobs have the format:
//     16 bytes - IV
//     64 bytes - Ciphertext
//     32 bytes - MAC
func DecryptItemKey(itemKey []byte, kp *KeyPair) (*KeyPair, error) {
	itemKey, err := authenticate(itemKey, kp)
	if err != nil {
		return nil, err
	}

	plaintext, err := decrypt(itemKey, kp)
	if err != nil {
		return nil, err
	}

	itemKP := &KeyPair{
		EncKey: plaintext[0:EncKeySize],
		MACKey: plaintext[EncKeySize:EncKeySize + MACKeySize],
	}

	return itemKP, nil
}
