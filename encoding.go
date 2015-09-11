package onepassword

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	ItemEncryptionKeySize = 32
	ItemMACKeySize        = 32
)

var (
	ErrIncompleteCiphertext = errors.New("Incomplete ciphertext")
	ErrIncompleteIV         = errors.New("Incomplete IV")
	ErrIncompleteMagic      = errors.New("Incomplete magic")
	ErrIncompleteMAC        = errors.New("Incomplete MAC")
	ErrInvalidMagic         = errors.New("Invalid magic")
	ErrIncorrectMAC         = errors.New("Incorrect MAC")

	OPDataMagic = []byte("opdata01")
)

type OPDataDecoder struct {
	encKey []byte  // Encryption key
	macKey []byte  // MAC key
}

func NewOPDataDecoder(encKey, macKey []byte) *OPDataDecoder {
	return &OPDataDecoder{encKey, macKey}
}

// Decode parses, authenticates, and decrypts opdata01 blobs.
func (d *OPDataDecoder) Decode(opdata []byte) ([]byte, error) {
	r := bytes.NewBuffer(opdata)

	// Read magic
	magic := make([]byte, len(OPDataMagic))
	n, err := r.Read(magic)
	if err != nil {
		return nil, err
	} else if n != len(magic) {
		return nil, ErrIncompleteMagic
	} else if !bytes.Equal(magic, OPDataMagic) {
		return nil, ErrInvalidMagic
	}

	// Read plaintext length
	var ptLen uint64
	err = binary.Read(r, binary.LittleEndian, &ptLen)
	if err != nil {
		return nil, err
	}

	// Read IV
	iv := make([]byte, aes.BlockSize)
	n, err = r.Read(iv)
	if err != nil {
		return nil, err
	} else if n != aes.BlockSize {
		return nil, ErrIncompleteIV
	}

	// Read ciphertext
	padLen := aes.BlockSize - (ptLen % aes.BlockSize)
	ctLen := ptLen + padLen
	ciphertext := make([]byte, ctLen)
	n, err = r.Read(ciphertext)
	if err != nil {
		return nil, err
	} else if uint64(n) != ctLen {
		return nil, ErrIncompleteCiphertext
	}

	// Read MAC
	msgMAC := make([]byte, sha256.Size)
	n, err = r.Read(msgMAC)
	if err != nil {
		return nil, err
	} else if n != sha256.Size {
		return nil, ErrIncompleteMAC
	}

	// Verify MAC
	data := opdata[0:len(opdata) - sha256.Size]
	mac := hmac.New(sha256.New, d.macKey)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(msgMAC, expectedMAC) {
		return nil, ErrIncorrectMAC
	}

	// Finally, decrypt!
	b, err := aes.NewCipher(d.encKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(b, iv)
	bm.CryptBlocks(plaintext, ciphertext)

	return plaintext[padLen:len(plaintext)], nil
}

type ItemKeyDecoder struct {
	encKey []byte  // Encryption key
	macKey []byte  // MAC key
}

func NewItemKeyDecoder(encKey, macKey []byte) *ItemKeyDecoder {
	return &ItemKeyDecoder{encKey, macKey}
}

// Decode parses, authenticates, and decode item encryption and MAC keys.
func (d *ItemKeyDecoder) Decode(itemKey []byte) (encKey, macKey []byte, err error) {
	r := bytes.NewBuffer(itemKey)

	// Read IV
	iv := make([]byte, aes.BlockSize)
	n, err := r.Read(iv)
	if err != nil {
		return nil, nil, err
	} else if n != aes.BlockSize {
		return nil, nil, ErrIncompleteIV
	}

	// Read ciphertext
	ciphertext := make([]byte, ItemEncryptionKeySize + ItemMACKeySize)
	n, err =  r.Read(ciphertext)
	if err != nil {
		return nil, nil, err
	} else if n != ItemEncryptionKeySize + ItemMACKeySize {
		return nil, nil, ErrIncompleteCiphertext
	}

	// Read MAC
	msgMAC := make([]byte, sha256.Size)
	n, err = r.Read(msgMAC)
	if err != nil {
		return nil, nil, err
	} else if n != sha256.Size {
		return nil, nil, ErrIncompleteMAC
	}

	// Verify MAC
	data := itemKey[0:len(itemKey) - sha256.Size]
	mac := hmac.New(sha256.New, d.macKey)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(msgMAC, expectedMAC) {
		return nil, nil, ErrIncorrectMAC
	}

	// Finally, decrypt!
	b, err := aes.NewCipher(d.encKey)
	if err != nil {
		return nil, nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(b, iv)
	bm.CryptBlocks(plaintext, ciphertext)

	return plaintext[0:ItemEncryptionKeySize], plaintext[ItemEncryptionKeySize:ItemEncryptionKeySize + ItemMACKeySize], nil
}
