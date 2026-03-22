// Package encode provides Base64 and hexadecimal encoding/decoding helpers.
package encode

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeBase64 returns the standard Base64 encoding of data (with padding, '+' and '/').
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// EncodeBase64URL returns the URL-safe Base64 encoding of data ('-' and '_', with padding).
func EncodeBase64URL(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// EncodeBase64Raw returns raw (no-padding) standard Base64 encoding.
func EncodeBase64Raw(data []byte) string {
	return base64.RawStdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a Base64 string, trying standard, URL-safe, raw standard,
// and raw URL-safe encodings in that order.  Leading/trailing whitespace is trimmed.
func DecodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid Base64 string (tried standard, URL-safe, and raw variants)")
}

// EncodeHex returns the lowercase hexadecimal encoding of data.
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes a hexadecimal string (case-insensitive, leading/trailing
// whitespace is trimmed).
func DecodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return b, nil
}
