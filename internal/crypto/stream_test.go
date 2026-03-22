package crypto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/gocryptic/gocryptic/internal/crypto"
)

// streamTestCases defines payloads used across all streaming tests.
var streamTestCases = []struct {
	name string
	size int
}{
	{"empty", 0},
	{"small (1 byte)", 1},
	{"one chunk (64KB)", 64 * 1024},
	{"multi-chunk (200KB)", 200 * 1024},
	{"non-aligned (100KB+1)", 100*1024 + 1},
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	if n == 0 {
		return []byte{}
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("generating random bytes: %v", err)
	}
	return b
}

func TestStreamAESGCMRoundtrip(t *testing.T) {
	for _, tc := range streamTestCases {
		t.Run(tc.name, func(t *testing.T) {
			pt := randomBytes(t, tc.size)

			var buf bytes.Buffer
			if err := crypto.EncryptStreamAESGCM(bytes.NewReader(pt), &buf, "streampass"); err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			var out bytes.Buffer
			if err := crypto.DecryptStreamAESGCM(bytes.NewReader(buf.Bytes()), &out, "streampass"); err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(pt, out.Bytes()) {
				t.Fatalf("plaintext mismatch after round-trip")
			}
		})
	}
}

func TestStreamChaCha20Roundtrip(t *testing.T) {
	for _, tc := range streamTestCases {
		t.Run(tc.name, func(t *testing.T) {
			pt := randomBytes(t, tc.size)

			var buf bytes.Buffer
			if err := crypto.EncryptStreamChaCha20(bytes.NewReader(pt), &buf, "streampass"); err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			var out bytes.Buffer
			if err := crypto.DecryptStreamChaCha20(bytes.NewReader(buf.Bytes()), &out, "streampass"); err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			if !bytes.Equal(pt, out.Bytes()) {
				t.Fatalf("plaintext mismatch after round-trip")
			}
		})
	}
}

func TestStreamAutoDetect(t *testing.T) {
	cases := []struct {
		name string
		fn   func(io.Reader, io.Writer, string) error
	}{
		{"aes-gcm", crypto.EncryptStreamAESGCM},
		{"chacha20", crypto.EncryptStreamChaCha20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt := []byte("auto-detect streaming test")
			var buf bytes.Buffer
			if err := c.fn(bytes.NewReader(pt), &buf, "pass"); err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			var out bytes.Buffer
			if err := crypto.DecryptStreamAuto(bytes.NewReader(buf.Bytes()), &out, "pass"); err != nil {
				t.Fatalf("auto-decrypt: %v", err)
			}
			if !bytes.Equal(pt, out.Bytes()) {
				t.Fatalf("mismatch")
			}
		})
	}
}

func TestStreamWrongPassword(t *testing.T) {
	pt := []byte("wrong password test")
	var buf bytes.Buffer
	if err := crypto.EncryptStreamAESGCM(bytes.NewReader(pt), &buf, "correct"); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	var out bytes.Buffer
	if err := crypto.DecryptStreamAESGCM(bytes.NewReader(buf.Bytes()), &out, "wrong"); err == nil {
		t.Fatal("expected error with wrong password, got nil")
	}
}

func TestStreamUniqueCiphertexts(t *testing.T) {
	pt := []byte("same plaintext every time")
	var buf1, buf2 bytes.Buffer
	if err := crypto.EncryptStreamAESGCM(bytes.NewReader(pt), &buf1, "pw"); err != nil {
		t.Fatal(err)
	}
	if err := crypto.EncryptStreamAESGCM(bytes.NewReader(pt), &buf2, "pw"); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatal("two encryptions produced identical ciphertext (nonce reuse)")
	}
}
