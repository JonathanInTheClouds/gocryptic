package cmd

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gocryptic/gocryptic/internal/sign"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data with an RSA or ECDSA private key",
	Long: `Create a digital signature for a file or string.

Supports RSA-PSS (SHA-256) and ECDSA P-256 (SHA-256, ASN.1 DER).
The key type is detected automatically from the PEM file.

The signature is written as a binary file (default: <input>.sig) or printed
as hex to stdout when no output file is specified.

EXAMPLES:
  # Sign a file with an RSA key
  gocryptic sign --file firmware.bin --key priv.pem

  # Sign a file with an ECDSA key; write sig to custom path
  gocryptic sign --file contract.pdf --key ec_priv.pem --output contract.sig

  # Sign a string, print hex signature to stdout
  gocryptic sign --input "release v1.0" --key priv.pem`,
	RunE: runSign,
}

var (
	signInput  string
	signFile   string
	signKey    string
	signOutput string
)

func init() {
	signCmd.Flags().StringVarP(&signInput, "input", "i", "",
		"String to sign")
	signCmd.Flags().StringVarP(&signFile, "file", "f", "",
		"File to sign")
	signCmd.Flags().StringVarP(&signKey, "key", "k", "",
		"Private key PEM file (RSA or ECDSA)")
	signCmd.Flags().StringVarP(&signOutput, "output", "o", "",
		"Output file for signature bytes (default: <input>.sig, or hex to stdout)")
	_ = signCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(signCmd)
}

func runSign(_ *cobra.Command, _ []string) error {
	var data []byte
	switch {
	case signInput != "":
		data = []byte(signInput)
	case signFile != "":
		var err error
		data, err = os.ReadFile(signFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", signFile, err)
		}
	case isStdin():
		var err error
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	default:
		return fmt.Errorf("no input specified — use --input, --file, or pipe to stdin")
	}

	kt, _ := sign.KeyType(signKey)
	fmt.Fprintf(os.Stderr, "Key type: %s\n", kt)

	sig, err := sign.Sign(data, signKey)
	if err != nil {
		return err
	}

	// Derive default output path.
	outPath := signOutput
	if outPath == "" && signFile != "" {
		outPath = signFile + ".sig"
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, sig, 0644); err != nil {
			return fmt.Errorf("writing signature: %w", err)
		}
		success("Signature → %s  (%d bytes)", outPath, len(sig))
		return nil
	}
	// Print as hex to stdout.
	fmt.Printf("%s\n", hex.EncodeToString(sig))
	return nil
}
