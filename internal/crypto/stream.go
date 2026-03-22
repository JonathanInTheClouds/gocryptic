package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	gorand "crypto/rand"

	gochacha "golang.org/x/crypto/chacha20poly1305"
)

// chunkSize is the plaintext size of each streaming chunk (64 KiB).
const chunkSize = 64 * 1024

// StreamThresholdWarn is the file size at which --stream is suggested.
const StreamThresholdWarn = 32 * 1024 * 1024 // 32 MB

// StreamThresholdStrong is the file size at which the warning becomes urgent.
const StreamThresholdStrong = 512 * 1024 * 1024 // 512 MB

// Streaming algorithm header bytes — distinct from in-memory variants.
const (
	StreamAlgoAESGCM   = byte(0x11)
	StreamAlgoChaCha20 = byte(0x13)
)

// ---------------------------------------------------------------------------
// Public encrypt
// ---------------------------------------------------------------------------

// EncryptStreamAESGCM reads from r and writes a streaming AES-256-GCM
// encrypted packet to w. Memory usage is O(chunkSize) regardless of input size.
func EncryptStreamAESGCM(r io.Reader, w io.Writer, password string) error {
	return streamEncrypt(r, w, password, StreamAlgoAESGCM)
}

// EncryptStreamChaCha20 reads from r and writes a streaming XChaCha20-Poly1305
// encrypted packet to w. Memory usage is O(chunkSize).
func EncryptStreamChaCha20(r io.Reader, w io.Writer, password string) error {
	return streamEncrypt(r, w, password, StreamAlgoChaCha20)
}

// ---------------------------------------------------------------------------
// Public decrypt
// ---------------------------------------------------------------------------

// DecryptStreamAESGCM reads a streaming AES-256-GCM packet from r and
// writes plaintext to w.
func DecryptStreamAESGCM(r io.Reader, w io.Writer, password string) error {
	return streamDecrypt(r, w, password, StreamAlgoAESGCM)
}

// DecryptStreamChaCha20 reads a streaming XChaCha20-Poly1305 packet from r
// and writes plaintext to w.
func DecryptStreamChaCha20(r io.Reader, w io.Writer, password string) error {
	return streamDecrypt(r, w, password, StreamAlgoChaCha20)
}

// DecryptStreamAuto peeks at the algorithm byte and dispatches accordingly.
func DecryptStreamAuto(r io.Reader, w io.Writer, password string) error {
	header := make([]byte, 5+saltSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("reading stream header: %w", err)
	}
	if !bytes.Equal(header[:4], magic) {
		return fmt.Errorf("invalid header: not a GoCryptic file")
	}
	algo := header[4]
	combined := io.MultiReader(bytes.NewReader(header), r)
	switch algo {
	case StreamAlgoAESGCM:
		return streamDecrypt(combined, w, password, StreamAlgoAESGCM)
	case StreamAlgoChaCha20:
		return streamDecrypt(combined, w, password, StreamAlgoChaCha20)
	default:
		return fmt.Errorf("unknown streaming algorithm byte: 0x%02x", algo)
	}
}

// ---------------------------------------------------------------------------
// Internal encrypt
// ---------------------------------------------------------------------------

func streamEncrypt(r io.Reader, w io.Writer, password string, algo byte) error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(gorand.Reader, salt); err != nil {
		return fmt.Errorf("salt generation: %w", err)
	}
	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("key derivation: %w", err)
	}
	aead, err := makeAEAD(algo, key)
	if err != nil {
		return err
	}

	// Header: magic(4) + algo(1) + salt(32)
	if _, err := w.Write(magic); err != nil {
		return fmt.Errorf("writing magic: %w", err)
	}
	if _, err := w.Write([]byte{algo}); err != nil {
		return fmt.Errorf("writing algo: %w", err)
	}
	if _, err := w.Write(salt); err != nil {
		return fmt.Errorf("writing salt: %w", err)
	}

	plainBuf := make([]byte, chunkSize)
	nonce := make([]byte, aead.NonceSize())
	sizeBuf := make([]byte, 4)

	for {
		n, readErr := io.ReadFull(r, plainBuf)
		if n == 0 && readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("reading input: %w", readErr)
		}

		if _, err := io.ReadFull(gorand.Reader, nonce); err != nil {
			return fmt.Errorf("nonce generation: %w", err)
		}

		ct := aead.Seal(nil, nonce, plainBuf[:n], nil)
		chunk := append(nonce, ct...)
		binary.BigEndian.PutUint32(sizeBuf, uint32(len(chunk)))

		if _, err := w.Write(sizeBuf); err != nil {
			return fmt.Errorf("writing chunk size: %w", err)
		}
		if _, err := w.Write(chunk); err != nil {
			return fmt.Errorf("writing chunk: %w", err)
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal decrypt
// ---------------------------------------------------------------------------

func streamDecrypt(r io.Reader, w io.Writer, password string, algo byte) error {
	header := make([]byte, 5+saltSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	if !bytes.Equal(header[:4], magic) {
		return fmt.Errorf("invalid header: not a GoCryptic file")
	}
	if header[4] != algo {
		return fmt.Errorf("algorithm mismatch: expected 0x%02x, got 0x%02x", algo, header[4])
	}
	salt := header[5 : 5+saltSize]

	key, err := deriveKey([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("key derivation: %w", err)
	}
	aead, err := makeAEAD(algo, key)
	if err != nil {
		return err
	}

	sizeBuf := make([]byte, 4)
	maxChunk := uint32(aead.NonceSize()) + uint32(chunkSize) + 64

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

		ns := aead.NonceSize()
		pt, err := aead.Open(nil, chunk[:ns], chunk[ns:], nil)
		if err != nil {
			return fmt.Errorf("chunk decryption failed (wrong password or corrupted data): %w", err)
		}

		if _, err := w.Write(pt); err != nil {
			return fmt.Errorf("writing plaintext: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func makeAEAD(algo byte, key []byte) (cipher.AEAD, error) {
	switch algo {
	case StreamAlgoAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case StreamAlgoChaCha20:
		return gochacha.NewX(key)
	default:
		return nil, fmt.Errorf("unsupported streaming algorithm: 0x%02x", algo)
	}
}