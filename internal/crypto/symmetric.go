// Package crypto provides symmetric and asymmetric encryption primitives.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Algorithm identifier bytes embedded in every GoCryptic packet header.
const (
	AlgoAESGCM   = byte(0x01)
	AlgoAESCBC   = byte(0x02)
	AlgoChaCha20 = byte(0x03)
	AlgoRSA      = byte(0x04)

	saltSize = 32 // scrypt salt length in bytes

	// scrypt parameters (N=2^15, r=8, p=1 → ~32 MB, ~100 ms on modern HW)
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

// magic is the 4-byte file header that identifies GoCryptic-encrypted data.
var magic = []byte("GCRY")

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// deriveKey derives a 32-byte key from a password and salt using scrypt.
func deriveKey(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, 32)
}

// buildPacket assembles: GCRY(4) + algo(1) + salt(32) + nonce + ciphertext.
func buildPacket(algo byte, salt, nonce, ct []byte) []byte {
	out := make([]byte, 0, 5+len(salt)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, algo)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

// parseHeader validates magic + algo byte, then returns salt and the payload.
func parseHeader(data []byte, algo byte) (salt, rest []byte, err error) {
	if len(data) < 5+saltSize {
		return nil, nil, fmt.Errorf("data too short to be a GoCryptic packet")
	}
	if !bytes.Equal(data[:4], magic) {
		return nil, nil, fmt.Errorf("invalid header: not a GoCryptic file")
	}
	if data[4] != algo {
		return nil, nil, fmt.Errorf("algorithm mismatch: expected 0x%02x, got 0x%02x", algo, data[4])
	}
	return data[5 : 5+saltSize], data[5+saltSize:], nil
}

// ---------------------------------------------------------------------------
// AES-256-GCM  (password-based, scrypt KDF)
// ---------------------------------------------------------------------------

// EncryptAESGCM encrypts plaintext with AES-256-GCM.
// Key is derived from password+salt via scrypt.
// Output format: GCRY(4) | AlgoAESGCM(1) | salt(32) | nonce(12) | ct+tag
func EncryptAESGCM(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt generation: %w", err)
	}
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}
	return buildPacket(AlgoAESGCM, salt, nonce, gcm.Seal(nil, nonce, plaintext, nil)), nil
}

// DecryptAESGCM decrypts an AES-256-GCM packet produced by EncryptAESGCM.
func DecryptAESGCM(data []byte, password string) ([]byte, error) {
	salt, rest, err := parseHeader(data, AlgoAESGCM)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	pt, err := gcm.Open(nil, rest[:ns], rest[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed (wrong password?): %w", err)
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// AES-256-CBC + HMAC-SHA256  (encrypt-then-MAC, scrypt KDF)
// ---------------------------------------------------------------------------

// EncryptAESCBC encrypts with AES-256-CBC using PKCS7 padding and a
// HMAC-SHA256 authentication tag (encrypt-then-MAC scheme).
// Two sub-keys are derived: 32 bytes for encryption, 32 bytes for HMAC.
// Output format: GCRY(4) | AlgoAESCBC(1) | salt(32) | iv(16) | hmac(32) | ct
func EncryptAESCBC(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt generation: %w", err)
	}
	// Derive 64 bytes; split into enc key (first 32) and MAC key (last 32).
	km, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 64)
	if err != nil {
		return nil, err
	}
	encKey, macKey := km[:32], km[32:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	// PKCS7 padding
	padLen := bs - len(plaintext)%bs
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	iv := make([]byte, bs)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("IV generation: %w", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// HMAC over salt | iv | ct
	mac := hmac.New(sha256.New, macKey)
	mac.Write(salt)
	mac.Write(iv)
	mac.Write(ct)
	macBytes := mac.Sum(nil)

	out := make([]byte, 0, 5+saltSize+bs+32+len(ct))
	out = append(out, magic...)
	out = append(out, AlgoAESCBC)
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, macBytes...)
	out = append(out, ct...)
	return out, nil
}

// DecryptAESCBC decrypts an AES-256-CBC packet produced by EncryptAESCBC.
func DecryptAESCBC(data []byte, password string) ([]byte, error) {
	if len(data) < 5+saltSize {
		return nil, fmt.Errorf("data too short")
	}
	if !bytes.Equal(data[:4], magic) || data[4] != AlgoAESCBC {
		return nil, fmt.Errorf("not a GoCryptic AES-CBC packet")
	}

	offset := 5
	salt := data[offset : offset+saltSize]
	offset += saltSize

	km, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 64)
	if err != nil {
		return nil, err
	}
	encKey, macKey := km[:32], km[32:]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	if len(data) < offset+bs+32 {
		return nil, fmt.Errorf("data too short for IV+HMAC")
	}
	iv := data[offset : offset+bs]
	offset += bs
	expectedMAC := data[offset : offset+32]
	offset += 32
	ct := data[offset:]

	// Verify MAC before decrypting (timing-safe comparison).
	mac := hmac.New(sha256.New, macKey)
	mac.Write(salt)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return nil, fmt.Errorf("authentication failed: wrong password or corrupted data")
	}

	if len(ct)%bs != 0 {
		return nil, fmt.Errorf("ciphertext length is not a multiple of the block size")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)

	// Remove PKCS7 padding.
	if len(pt) == 0 {
		return nil, fmt.Errorf("empty plaintext after decryption")
	}
	padLen := int(pt[len(pt)-1])
	if padLen == 0 || padLen > bs {
		return nil, fmt.Errorf("invalid PKCS7 padding byte: %d", padLen)
	}
	return pt[:len(pt)-padLen], nil
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305  (password-based, scrypt KDF)
// ---------------------------------------------------------------------------

// EncryptChaCha20 encrypts with XChaCha20-Poly1305 (256-bit key, 192-bit nonce).
// Output format: GCRY(4) | AlgoChaCha20(1) | salt(32) | nonce(24) | ct+tag
func EncryptChaCha20(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt generation: %w", err)
	}
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key) // XChaCha20: 24-byte nonce
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation: %w", err)
	}
	return buildPacket(AlgoChaCha20, salt, nonce, aead.Seal(nil, nonce, plaintext, nil)), nil
}

// DecryptChaCha20 decrypts an XChaCha20-Poly1305 packet produced by EncryptChaCha20.
func DecryptChaCha20(data []byte, password string) ([]byte, error) {
	salt, rest, err := parseHeader(data, AlgoChaCha20)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(rest) < ns {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}
	pt, err := aead.Open(nil, rest[:ns], rest[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 decryption failed (wrong password?): %w", err)
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// Auto-detect
// ---------------------------------------------------------------------------

// DecryptAuto reads the algorithm byte from the packet header and dispatches.
func DecryptAuto(data []byte, password string) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short to detect algorithm")
	}
	if !bytes.Equal(data[:4], magic) {
		return nil, fmt.Errorf("invalid header: not a GoCryptic file")
	}
	switch data[4] {
	case AlgoAESGCM:
		return DecryptAESGCM(data, password)
	case AlgoAESCBC:
		return DecryptAESCBC(data, password)
	case AlgoChaCha20:
		return DecryptChaCha20(data, password)
	case AlgoRSA:
		return nil, fmt.Errorf("RSA-encrypted file requires a private key — use --algo rsa --rsa-key <priv.pem>")
	default:
		return nil, fmt.Errorf("unknown algorithm byte: 0x%02x", data[4])
	}
}

// ---------------------------------------------------------------------------
// Raw AES-GCM helpers (used internally by hybrid RSA encryption)
// ---------------------------------------------------------------------------

// EncryptRawAESGCM encrypts with a raw 32-byte key (no KDF).
// Returns: nonce(12) | ciphertext+tag
func EncryptRawAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...), nil
}

// DecryptRawAESGCM decrypts data produced by EncryptRawAESGCM.
func DecryptRawAESGCM(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("encrypted data too short")
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM (raw) decryption failed: %w", err)
	}
	return pt, nil
}
