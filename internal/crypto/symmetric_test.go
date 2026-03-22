package crypto_test

import (
	"bytes"
	"testing"

	"github.com/gocryptic/gocryptic/internal/crypto"
)

var testMessages = []struct {
	name      string
	plaintext []byte
}{
	{"empty", []byte{}},
	{"short", []byte("hello world")},
	{"binary", []byte{0x00, 0x01, 0xfe, 0xff, 0x80}},
	{"1KB", bytes.Repeat([]byte("A"), 1024)},
	{"16KB", bytes.Repeat([]byte("BinaryData!"), 1500)},
}

func TestAESGCM(t *testing.T) {
	for _, tc := range testMessages {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := crypto.EncryptAESGCM(tc.plaintext, "secret-pass")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := crypto.DecryptAESGCM(ct, "secret-pass")
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("roundtrip mismatch")
			}
		})
	}
}

func TestAESGCMWrongPassword(t *testing.T) {
	ct, _ := crypto.EncryptAESGCM([]byte("secret"), "correct")
	if _, err := crypto.DecryptAESGCM(ct, "wrong"); err == nil {
		t.Fatal("expected decryption to fail with wrong password")
	}
}

func TestAESCBC(t *testing.T) {
	for _, tc := range testMessages {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := crypto.EncryptAESCBC(tc.plaintext, "another-pass")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := crypto.DecryptAESCBC(ct, "another-pass")
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("roundtrip mismatch")
			}
		})
	}
}

func TestAESCBCWrongPassword(t *testing.T) {
	ct, _ := crypto.EncryptAESCBC([]byte("secret"), "correct")
	if _, err := crypto.DecryptAESCBC(ct, "wrong"); err == nil {
		t.Fatal("expected authentication to fail with wrong password")
	}
}

func TestChaCha20(t *testing.T) {
	for _, tc := range testMessages {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := crypto.EncryptChaCha20(tc.plaintext, "chacha-pass")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := crypto.DecryptChaCha20(ct, "chacha-pass")
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("roundtrip mismatch")
			}
		})
	}
}

func TestDecryptAuto(t *testing.T) {
	cases := []struct {
		name string
		fn   func([]byte, string) ([]byte, error)
	}{
		{"aes-gcm", crypto.EncryptAESGCM},
		{"aes-cbc", crypto.EncryptAESCBC},
		{"chacha20", crypto.EncryptChaCha20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt := []byte("auto-detect plaintext")
			ct, err := c.fn(pt, "pass")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := crypto.DecryptAuto(ct, "pass")
			if err != nil {
				t.Fatalf("auto-decrypt: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatal("mismatch")
			}
		})
	}
}

func TestNoncesAreRandom(t *testing.T) {
	pt := []byte("same plaintext, different ciphertext each time")
	ct1, _ := crypto.EncryptAESGCM(pt, "pw")
	ct2, _ := crypto.EncryptAESGCM(pt, "pw")
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same data produced identical ciphertext (nonce reuse!)")
	}
}
