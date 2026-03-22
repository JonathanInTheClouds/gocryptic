// Package hash provides cryptographic hashing utilities.
package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	gohash "hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Supported algorithm name constants.
const (
	MD5     = "md5"
	SHA1    = "sha1"
	SHA256  = "sha256"
	SHA384  = "sha384"
	SHA512  = "sha512"
	SHA3256 = "sha3-256"
	SHA3512 = "sha3-512"
)

// orderedAlgos defines the canonical display order.
var orderedAlgos = []string{MD5, SHA1, SHA256, SHA384, SHA512, SHA3256, SHA3512}

// Algorithms returns all supported algorithm names in canonical order.
func Algorithms() []string { return orderedAlgos }

// newHasher returns a fresh hash.Hash for the named algorithm.
func newHasher(algo string) (gohash.Hash, error) {
	switch strings.ToLower(algo) {
	case MD5:
		return md5.New(), nil
	case SHA1:
		return sha1.New(), nil
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	case SHA3256:
		return sha3.New256(), nil
	case SHA3512:
		return sha3.New512(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q  (supported: %s)",
			algo, strings.Join(orderedAlgos, ", "))
	}
}

// Sum computes the hash of in-memory data and returns a lowercase hex string.
func Sum(data []byte, algo string) (string, error) {
	h, err := newHasher(algo)
	if err != nil {
		return "", err
	}
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SumFile streams a file through the hasher and returns a lowercase hex string.
// For large files this avoids loading the whole file into memory.
func SumFile(path, algo string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	h, err := newHasher(algo)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SumAll computes hashes with every supported algorithm and returns a map
// of algorithm → hex-digest.
func SumAll(data []byte) map[string]string {
	result := make(map[string]string, len(orderedAlgos))
	for _, algo := range orderedAlgos {
		if h, err := Sum(data, algo); err == nil {
			result[algo] = h
		}
	}
	return result
}

// SumFileAll reads the file once and hashes it with every algorithm,
// returning a map of algorithm → hex-digest.
func SumFileAll(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	// Build a slice of all hashers.
	hashers := make([]gohash.Hash, len(orderedAlgos))
	writers := make([]io.Writer, len(orderedAlgos))
	for i, algo := range orderedAlgos {
		h, _ := newHasher(algo)
		hashers[i] = h
		writers[i] = h
	}

	if _, err := io.Copy(io.MultiWriter(writers...), f); err != nil {
		return nil, fmt.Errorf("hashing %s: %w", path, err)
	}

	result := make(map[string]string, len(orderedAlgos))
	for i, algo := range orderedAlgos {
		result[algo] = hex.EncodeToString(hashers[i].Sum(nil))
	}
	return result, nil
}
