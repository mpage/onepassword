package onepassword

import (
	"testing"
)

func TestDecodeInsufficientOPData(t *testing.T) {
	dec := NewOPDataDecoder()
	_, err := dec.DecodeBytes([]byte("short"))
	if err == nil {
		t.Errorf("Unexpectedly succeeded.")
	} else if err != ErrShortRead {
		t.Errorf("Unexpected error returned.")
	}
}

func TestDecodeInvalidOPDataMagic(t *testing.T) {
	dec := NewOPDataDecoder()
	_, err := dec.DecodeBytes([]byte("invalidx"))
	if err == nil {
		t.Errorf("Unexpectedly succeeded.")
	} else if err != ErrInvalidOPDataMagic {
		t.Errorf("Unexpected error returned.")
	}
}

func TestDecodeCorruptOPDataPlaintextLen(t *testing.T) {
	dec := NewOPDataDecoder()
	_, err := dec.DecodeBytes([]byte("opdata01xx"))
	if err == nil {
		t.Errorf("Unexpectedly succeeded")
	}
}

func TestDecodeValidOPData(t *testing.T) {
	dec := NewOPDataDecoder()
	opdata := getValidOPData()
	_, err := dec.DecodeBytes(opdata)
	if err != nil {
		t.Fatalf("Failed decoding valid opdata: %s", err.Error())
	}
}
