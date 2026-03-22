package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/gocryptic/gocryptic/internal/crypto"
)

// generateECDHTestKeys writes a fresh ECDSA P-256 key pair to temp files
// and returns their paths.
func generateECDHTestKeys(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	privPath = filepath.Join(dir, "priv.pem")
	pubPath = filepath.Join(dir, "pub.pem")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatalf("writing private key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return privPath, pubPath
}

func TestECDHRoundtrip(t *testing.T) {
	privPath, pubPath := generateECDHTestKeys(t)

	messages := [][]byte{
		{},
		[]byte("hello ECDH"),
		bytes.Repeat([]byte("A"), 4096),
	}

	for _, msg := range messages {
		ct, err := crypto.EncryptECDH(msg, pubPath)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		pt, err := crypto.DecryptECDH(ct, privPath)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(msg, pt) {
			t.Fatalf("plaintext mismatch")
		}
	}
}

func TestECDHWrongKey(t *testing.T) {
	_, pubPath := generateECDHTestKeys(t)
	wrongPrivPath, _ := generateECDHTestKeys(t)

	ct, err := crypto.EncryptECDH([]byte("secret"), pubPath)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := crypto.DecryptECDH(ct, wrongPrivPath); err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestECDHUniqueCiphertexts(t *testing.T) {
	_, pubPath := generateECDHTestKeys(t)
	msg := []byte("same message")

	ct1, _ := crypto.EncryptECDH(msg, pubPath)
	ct2, _ := crypto.EncryptECDH(msg, pubPath)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same message produced identical ciphertext")
	}
}

func TestECDHStreamRoundtrip(t *testing.T) {
	privPath, pubPath := generateECDHTestKeys(t)

	sizes := []int{0, 1, 64*1024, 200*1024}
	for _, size := range sizes {
		pt := randomBytes(t, size)

		var buf bytes.Buffer
		if err := crypto.EncryptECDHStream(bytes.NewReader(pt), &buf, pubPath); err != nil {
			t.Fatalf("stream encrypt (size=%d): %v", size, err)
		}

		var out bytes.Buffer
		if err := crypto.DecryptECDHStream(bytes.NewReader(buf.Bytes()), &out, privPath); err != nil {
			t.Fatalf("stream decrypt (size=%d): %v", size, err)
		}

		if !bytes.Equal(pt, out.Bytes()) {
			t.Fatalf("stream roundtrip mismatch (size=%d)", size)
		}
	}
}
