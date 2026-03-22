package tui

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/gocryptic/gocryptic/internal/sign"
)

func encodeBase64(data []byte) string    { return base64.StdEncoding.EncodeToString(data) }
func encodeBase64URL(data []byte) string { return base64.URLEncoding.EncodeToString(data) }
func encodeBase64Raw(data []byte) string { return base64.RawStdEncoding.EncodeToString(data) }
func encodeHex(data []byte) string       { return hex.EncodeToString(data) }

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return base64.StdEncoding.DecodeString(s)
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(strings.ToLower(s)))
}

func signData(data []byte, privKeyPath string) ([]byte, error) {
	return sign.Sign(data, privKeyPath)
}

func verifyData(data, sig []byte, pubKeyPath string) error {
	return sign.Verify(data, sig, pubKeyPath)
}

// copyToClipboard writes s to the system clipboard.
// Returns true on success, false if clipboard is unavailable.
func copyToClipboard(s string) bool {
	// Strip display wrapping newlines — copy the raw single-line value.
	raw := strings.ReplaceAll(s, "\n", "")
	return clipboard.WriteAll(raw) == nil
}