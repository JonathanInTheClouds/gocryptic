// Package keygen provides key and password generation utilities.
package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateAESKey returns a cryptographically random AES key.
// bits must be 128, 192, or 256.
func GenerateAESKey(bits int) ([]byte, error) {
	if bits != 128 && bits != 192 && bits != 256 {
		return nil, fmt.Errorf("AES key size must be 128, 192, or 256 bits (got %d)", bits)
	}
	key := make([]byte, bits/8)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating AES key: %w", err)
	}
	return key, nil
}

// GenerateChaChaKey returns a cryptographically random 256-bit key
// suitable for ChaCha20-Poly1305 / XChaCha20-Poly1305.
func GenerateChaChaKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating ChaCha20 key: %w", err)
	}
	return key, nil
}

// GenerateRSAKeyPair generates an RSA key pair and writes PEM files.
// privPath is written with mode 0600; pubPath with mode 0644.
// bits must be at least 2048.
func GenerateRSAKeyPair(bits int, privPath, pubPath string) error {
	if bits < 2048 {
		return fmt.Errorf("RSA key must be at least 2048 bits for security (got %d)", bits)
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("generating RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0600); err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}
	return writePEM(pubPath, "PUBLIC KEY", pubDER, 0644)
}

// GenerateECDSAKeyPair generates an ECDSA P-256 key pair and writes PEM files.
// privPath is written with mode 0600; pubPath with mode 0644.
func GenerateECDSAKeyPair(privPath, pubPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ECDSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling ECDSA private key: %w", err)
	}
	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0600); err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling ECDSA public key: %w", err)
	}
	return writePEM(pubPath, "PUBLIC KEY", pubDER, 0644)
}

// GeneratePassword returns a cryptographically secure random password.
// If useSpecial is true, a set of common special characters is included.
func GeneratePassword(length int, useSpecial bool) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if useSpecial {
		chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
	}
	bigLen := big.NewInt(int64(len(chars)))
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, bigLen)
		if err != nil {
			return "", fmt.Errorf("random index generation: %w", err)
		}
		result[i] = chars[n.Int64()]
	}
	return string(result), nil
}

// writePEM encodes der as a PEM block and writes it to path with the given permissions.
func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("writing PEM to %s: %w", path, err)
	}
	return nil
}
