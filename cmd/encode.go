package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gocryptic/gocryptic/internal/encode"
	"github.com/spf13/cobra"
)

var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "Encode or decode data using Base64 or Hex",
	Long: `Encode or decode arbitrary data in Base64 (standard, URL-safe, raw) or hexadecimal.

FORMATS:
  base64      Standard Base64 with padding (RFC 4648 §4)
  base64url   URL-safe Base64 with padding (RFC 4648 §5)
  base64raw   Raw (no-padding) standard Base64
  hex         Lowercase hexadecimal (0-9, a-f)

EXAMPLES:
  # Base64-encode a string
  gocryptic encode --format base64 --input "hello, world!"

  # Base64-decode (auto-detects variant)
  gocryptic encode --decode --format base64 --input "aGVsbG8sIHdvcmxkIQ=="

  # Hex-encode a file
  gocryptic encode --format hex --file logo.png

  # Decode hex from stdin
  echo "68656c6c6f" | gocryptic encode --decode --format hex`,
	RunE: runEncode,
}

var (
	encFormat string
	encDecode bool
	encInput  string
	encFile   string
	encOut    string
)

func init() {
	encodeCmd.Flags().StringVarP(&encFormat, "format", "F", "base64",
		"Encoding format: base64 | base64url | base64raw | hex")
	encodeCmd.Flags().BoolVarP(&encDecode, "decode", "d", false,
		"Decode instead of encode")
	encodeCmd.Flags().StringVarP(&encInput, "input", "i", "",
		"String to encode/decode")
	encodeCmd.Flags().StringVarP(&encFile, "file", "f", "",
		"File to encode/decode")
	encodeCmd.Flags().StringVarP(&encOut, "output", "o", "",
		"Write result to file instead of stdout")
	rootCmd.AddCommand(encodeCmd)
}

func runEncode(_ *cobra.Command, _ []string) error {
	// Read raw input.
	var raw []byte
	switch {
	case encInput != "":
		raw = []byte(encInput)
	case encFile != "":
		var err error
		raw, err = os.ReadFile(encFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", encFile, err)
		}
	case isStdin():
		var err error
		raw, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	default:
		return fmt.Errorf("no input specified — use --input, --file, or pipe to stdin")
	}

	var result []byte
	var err error

	if encDecode {
		result, err = decodeData(raw)
	} else {
		result, err = encodeData(raw)
	}
	if err != nil {
		return err
	}

	if encOut != "" {
		if err := os.WriteFile(encOut, result, 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		success("Written → %s", encOut)
		return nil
	}
	_, err = os.Stdout.Write(result)
	if err == nil && !strings.HasSuffix(string(result), "\n") {
		fmt.Println() // ensure trailing newline on terminal
	}
	return err
}

func encodeData(data []byte) ([]byte, error) {
	switch strings.ToLower(encFormat) {
	case "base64":
		return []byte(encode.EncodeBase64(data)), nil
	case "base64url":
		return []byte(encode.EncodeBase64URL(data)), nil
	case "base64raw":
		return []byte(encode.EncodeBase64Raw(data)), nil
	case "hex":
		return []byte(encode.EncodeHex(data)), nil
	default:
		return nil, fmt.Errorf("unknown format %q  (choices: base64, base64url, base64raw, hex)", encFormat)
	}
}

func decodeData(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	switch strings.ToLower(encFormat) {
	case "base64", "base64url", "base64raw":
		return encode.DecodeBase64(s)
	case "hex":
		return encode.DecodeHex(s)
	default:
		return nil, fmt.Errorf("unknown format %q  (choices: base64, base64url, base64raw, hex)", encFormat)
	}
}
