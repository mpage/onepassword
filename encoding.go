package onepassword

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
)

var OPDataMagic = []byte("opdata01")

var (
	ErrShortRead = errors.New("Unable to read desired amount of data.")
	ErrInvalidOPDataMagic =  errors.New("Invalid magic.")
)


// OPData contains the decoded but still encrypted form of the OPData
type OPData struct {
	PlaintextLen uint64
	Ciphertext   []byte // Encrypted IV + Padding + Plaintext
}

type OPDataDecoder struct {
}

func NewOPDataDecoder() *OPDataDecoder {
	return &OPDataDecoder{}
}

func (d *OPDataDecoder) Decode(r io.Reader) (*OPData, error) {
	// Read magic
	magic := make([]byte, len(OPDataMagic))
	n, err := r.Read(magic)
	if err != nil {
		return nil, err
	} else if n != len(magic) {
		return nil, ErrShortRead
	} else if !bytes.Equal(magic, OPDataMagic) {
		return nil, ErrInvalidOPDataMagic
	}

	// Read plaintext length
	var ptLen uint64
	err = binary.Read(r, binary.LittleEndian, &ptLen)
	if err != nil {
		return nil, err
	}

	// Remainder is ciphertext.
	ciphertext, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &OPData{ptLen, ciphertext}, nil
}

func (d *OPDataDecoder) DecodeBytes(bs []byte) (*OPData, error) {
	buf := bytes.NewBuffer(bs)
	return d.Decode(buf)
}
