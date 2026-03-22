package encode_test

import (
	"bytes"
	"testing"

	"github.com/gocryptic/gocryptic/internal/encode"
)

var testInputs = [][]byte{
	{},
	[]byte("hello, world"),
	{0x00, 0xFF, 0x80, 0x7F},
	bytes.Repeat([]byte("Go!"), 100),
}

func TestBase64Roundtrip(t *testing.T) {
	for _, in := range testInputs {
		enc := encode.EncodeBase64(in)
		out, err := encode.DecodeBase64(enc)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("roundtrip failed")
		}
	}
}

func TestBase64URLRoundtrip(t *testing.T) {
	for _, in := range testInputs {
		enc := encode.EncodeBase64URL(in)
		out, err := encode.DecodeBase64(enc)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("URL-safe roundtrip failed")
		}
	}
}

func TestHexRoundtrip(t *testing.T) {
	for _, in := range testInputs {
		enc := encode.EncodeHex(in)
		out, err := encode.DecodeHex(enc)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(in, out) {
			t.Fatalf("hex roundtrip failed")
		}
	}
}

func TestHexKnown(t *testing.T) {
	if got := encode.EncodeHex([]byte("abc")); got != "616263" {
		t.Fatalf("expected 616263, got %s", got)
	}
}

func TestDecodeBase64Invalid(t *testing.T) {
	if _, err := encode.DecodeBase64("!!!not base64!!!"); err == nil {
		t.Fatal("expected error decoding invalid base64")
	}
}
