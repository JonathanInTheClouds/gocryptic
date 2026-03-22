package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

// EncryptRSA performs hybrid encryption: a random AES-256 session key is
// encrypted with RSA-OAEP(SHA-256), and the plaintext is encrypted with that
// session key using AES-256-GCM.  This supports arbitrarily large inputs.
//
// Output format:
//
//	GCRY(4) | AlgoRSA(1) | rsaKeyLen(4, big-endian) | encRSAKey | aesGCMData
func EncryptRSA(plaintext []byte, publicKeyPath string) ([]byte, error) {
	rsaPub, err := loadRSAPublicKey(publicKeyPath)
	if err != nil {
		return nil, err
	}

	// Generate a random 256-bit AES session key.
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("generating session key: %w", err)
	}

	// Encrypt the session key with RSA-OAEP.
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, sessionKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption: %w", err)
	}

	// Encrypt plaintext with AES-GCM using the session key.
	encData, err := EncryptRawAESGCM(plaintext, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM session encryption: %w", err)
	}

	// Assemble packet.
	keyLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLenBuf, uint32(len(encKey)))

	out := make([]byte, 0, 5+4+len(encKey)+len(encData))
	out = append(out, magic...)
	out = append(out, AlgoRSA)
	out = append(out, keyLenBuf...)
	out = append(out, encKey...)
	out = append(out, encData...)
	return out, nil
}

// DecryptRSA decrypts a hybrid RSA+AES-GCM packet produced by EncryptRSA.
func DecryptRSA(data []byte, privateKeyPath string) ([]byte, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("data too short")
	}
	if !bytes.Equal(data[:4], magic) || data[4] != AlgoRSA {
		return nil, fmt.Errorf("not a GoCryptic RSA packet")
	}

	keyLen := int(binary.BigEndian.Uint32(data[5:9]))
	if len(data) < 9+keyLen {
		return nil, fmt.Errorf("data too short for RSA-encrypted key (need %d bytes)", 9+keyLen)
	}
	encKey := data[9 : 9+keyLen]
	encData := data[9+keyLen:]

	rsaPriv, err := loadRSAPrivateKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	// Recover session key.
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption: %w", err)
	}

	// Decrypt payload.
	pt, err := DecryptRawAESGCM(encData, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption: %w", err)
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// PEM key loaders
// ---------------------------------------------------------------------------

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", path, err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an RSA public key", path)
	}
	return rsaPub, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", path, err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	// Try PKCS8 first (gocryptic keygen output), then PKCS1.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaPriv, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key in %s is not RSA", path)
		}
		return rsaPriv, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unable to parse RSA private key from %s (tried PKCS8 and PKCS1)", path)
}
