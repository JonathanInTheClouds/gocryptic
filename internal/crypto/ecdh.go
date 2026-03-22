package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	goecdh "crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// AlgoECDH is the packet header byte for ECDH-encrypted data.
const AlgoECDH = byte(0x05)

// ecdhInfo is the HKDF info string — binds the derived key to this application.
const ecdhInfo = "GoCryptic-ECDH-AES256GCM-v1"

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

// EncryptECDH encrypts plaintext using the recipient's ECDH public key.
// No password is required — only the recipient's private key can decrypt.
//
// Packet format:
//
//	GCRY(4) | AlgoECDH(1) | ephPubLen(2, big-endian) | ephPubBytes | nonce(12) | ct+tag
func EncryptECDH(plaintext []byte, recipientPubKeyPath string) ([]byte, error) {
	recipientPub, err := loadECDHPublicKey(recipientPubKeyPath)
	if err != nil {
		return nil, err
	}
	return encryptECDH(plaintext, recipientPub)
}

// EncryptECDHStream encrypts from r to w using the recipient's ECDH public key.
func EncryptECDHStream(r io.Reader, w io.Writer, recipientPubKeyPath string) error {
	recipientPub, err := loadECDHPublicKey(recipientPubKeyPath)
	if err != nil {
		return err
	}

	// Generate ephemeral key pair.
	ephPriv, ephPub, sharedKey, err := ecdhHandshake(recipientPub)
	_ = ephPriv
	if err != nil {
		return err
	}

	ephPubBytes := ephPub.Bytes()
	aesKey, err := hkdfExpand(sharedKey, ephPubBytes, recipientPub.Bytes())
	if err != nil {
		return err
	}

	// Write header.
	if err := writeECDHHeader(w, ephPubBytes); err != nil {
		return err
	}

	// Stream the data using the derived key.
	return streamEncryptWithKey(r, w, aesKey)
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

// DecryptECDH decrypts an ECDH-encrypted packet using the recipient's private key.
func DecryptECDH(data []byte, privateKeyPath string) ([]byte, error) {
	priv, err := loadECDHPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return decryptECDH(data, priv)
}

// DecryptECDHStream decrypts a streaming ECDH packet from r to w.
func DecryptECDHStream(r io.Reader, w io.Writer, privateKeyPath string) error {
	priv, err := loadECDHPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}

	// Read and validate header.
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	if !bytes.Equal(header[:4], magic) || header[4] != AlgoECDH {
		return fmt.Errorf("not a GoCryptic ECDH packet")
	}

	ephPubBytes, err := readEphemeralPub(r)
	if err != nil {
		return err
	}

	aesKey, err := ecdhDeriveKey(priv, ephPubBytes)
	if err != nil {
		return err
	}

	return streamDecryptWithKey(r, w, aesKey)
}

// ---------------------------------------------------------------------------
// Internal encrypt/decrypt
// ---------------------------------------------------------------------------

func encryptECDH(plaintext []byte, recipientPub *goecdh.PublicKey) ([]byte, error) {
	_, ephPub, sharedKey, err := ecdhHandshake(recipientPub)
	if err != nil {
		return nil, err
	}

	ephPubBytes := ephPub.Bytes()
	aesKey, err := hkdfExpand(sharedKey, ephPubBytes, recipientPub.Bytes())
	if err != nil {
		return nil, err
	}

	// Encrypt with AES-256-GCM.
	block, err := aes.NewCipher(aesKey)
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
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Assemble packet.
	var buf bytes.Buffer
	if err := writeECDHHeader(&buf, ephPubBytes); err != nil {
		return nil, err
	}
	buf.Write(nonce)
	buf.Write(ct)
	return buf.Bytes(), nil
}

func decryptECDH(data []byte, priv *goecdh.PrivateKey) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short")
	}
	if !bytes.Equal(data[:4], magic) || data[4] != AlgoECDH {
		return nil, fmt.Errorf("not a GoCryptic ECDH packet")
	}

	r := bytes.NewReader(data[5:])
	ephPubBytes, err := readEphemeralPub(r)
	if err != nil {
		return nil, err
	}

	aesKey, err := ecdhDeriveKey(priv, ephPubBytes)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	remaining, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(remaining) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	pt, err := gcm.Open(nil, remaining[:ns], remaining[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("ECDH decryption failed (wrong key?): %w", err)
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// ECDH handshake helpers
// ---------------------------------------------------------------------------

// ecdhHandshake generates an ephemeral P-256 key pair and computes the
// shared ECDH secret with the recipient's public key.
func ecdhHandshake(recipientPub *goecdh.PublicKey) (*goecdh.PrivateKey, *goecdh.PublicKey, []byte, error) {
	ephPriv, err := goecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	return ephPriv, ephPriv.PublicKey(), shared, nil
}

// ecdhDeriveKey recovers the shared secret from the recipient private key
// and the sender's ephemeral public key, then expands it into an AES key.
func ecdhDeriveKey(priv *goecdh.PrivateKey, ephPubBytes []byte) ([]byte, error) {
	ephPub, err := goecdh.P256().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}
	return hkdfExpand(shared, ephPubBytes, priv.PublicKey().Bytes())
}

// hkdfExpand derives a 32-byte AES key from the shared secret using HKDF-SHA256.
// The ephemeral public key bytes and recipient public key bytes are used as salt
// to bind the derived key to this specific exchange.
func hkdfExpand(shared, ephPubBytes, recipientPubBytes []byte) ([]byte, error) {
	salt := append(ephPubBytes, recipientPubBytes...)
	h := hkdf.New(sha256.New, shared, salt, []byte(ecdhInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("HKDF expansion: %w", err)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// Packet I/O helpers
// ---------------------------------------------------------------------------

// writeECDHHeader writes: GCRY(4) | AlgoECDH(1) | ephPubLen(2) | ephPubBytes
func writeECDHHeader(w io.Writer, ephPubBytes []byte) error {
	if _, err := w.Write(magic); err != nil {
		return err
	}
	if _, err := w.Write([]byte{AlgoECDH}); err != nil {
		return err
	}
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(ephPubBytes)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(ephPubBytes)
	return err
}

// readEphemeralPub reads the 2-byte length prefix then the ephemeral public key bytes.
func readEphemeralPub(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("reading ephemeral pub key length: %w", err)
	}
	pubLen := binary.BigEndian.Uint16(lenBuf)
	if pubLen == 0 || pubLen > 256 {
		return nil, fmt.Errorf("invalid ephemeral public key length: %d", pubLen)
	}
	pub := make([]byte, pubLen)
	if _, err := io.ReadFull(r, pub); err != nil {
		return nil, fmt.Errorf("reading ephemeral public key: %w", err)
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// Streaming with a raw AES key (no password/KDF)
// ---------------------------------------------------------------------------

// streamEncryptWithKey streams AES-256-GCM chunks using a raw key (no KDF).
// Format: same as streamEncrypt but without the salt header field.
func streamEncryptWithKey(r io.Reader, w io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plainBuf := make([]byte, chunkSize)
	nonce := make([]byte, gcm.NonceSize())
	sizeBuf := make([]byte, 4)

	for {
		n, readErr := io.ReadFull(r, plainBuf)
		if n == 0 && readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("reading input: %w", readErr)
		}
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("nonce generation: %w", err)
		}
		ct := gcm.Seal(nil, nonce, plainBuf[:n], nil)
		chunk := append(nonce, ct...)
		binary.BigEndian.PutUint32(sizeBuf, uint32(len(chunk)))
		if _, err := w.Write(sizeBuf); err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	return nil
}

// streamDecryptWithKey decrypts AES-256-GCM chunks using a raw key.
func streamDecryptWithKey(r io.Reader, w io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	sizeBuf := make([]byte, 4)
	ns := gcm.NonceSize()
	maxChunk := uint32(ns) + uint32(chunkSize) + 64

	for {
		_, err := io.ReadFull(r, sizeBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading chunk size: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(sizeBuf)
		if chunkLen == 0 || chunkLen > maxChunk {
			return fmt.Errorf("invalid chunk length: %d", chunkLen)
		}
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return fmt.Errorf("reading chunk: %w", err)
		}
		pt, err := gcm.Open(nil, chunk[:ns], chunk[ns:], nil)
		if err != nil {
			return fmt.Errorf("chunk decryption failed: %w", err)
		}
		if _, err := w.Write(pt); err != nil {
			return fmt.Errorf("writing plaintext: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// PEM key loaders
// ---------------------------------------------------------------------------

func loadECDHPublicKey(path string) (*goecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", path, err)
	}

	// Parse PKIX public key.
	pub, err := parseECDHPublicKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDH public key from %s: %w", path, err)
	}
	return pub, nil
}

func loadECDHPrivateKey(path string) (*goecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", path, err)
	}
	priv, err := parseECDHPrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDH private key from %s: %w", path, err)
	}
	return priv, nil
}