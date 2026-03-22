package cmd

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gocryptic/gocryptic/internal/sign"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a digital signature",
	Long: `Verify that a digital signature is valid for given data and public key.

Supports RSA-PSS (SHA-256) and ECDSA P-256 (SHA-256, ASN.1 DER).
The key type is detected automatically from the PEM file.

EXAMPLES:
  # Verify a signature file against a file
  gocryptic verify --file firmware.bin --sig firmware.bin.sig --key pub.pem

  # Verify a hex signature string
  gocryptic verify --input "release v1.0" --sig-hex <hex> --key ec_pub.pem`,
	RunE: runVerify,
}

var (
	verifyInput  string
	verifyFile   string
	verifySig    string
	verifySigHex string
	verifyKey    string
)

func init() {
	verifyCmd.Flags().StringVarP(&verifyInput, "input", "i", "",
		"String whose signature should be verified")
	verifyCmd.Flags().StringVarP(&verifyFile, "file", "f", "",
		"File whose signature should be verified")
	verifyCmd.Flags().StringVarP(&verifySig, "sig", "s", "",
		"Signature file (binary)")
	verifyCmd.Flags().StringVar(&verifySigHex, "sig-hex", "",
		"Signature as a hex string")
	verifyCmd.Flags().StringVarP(&verifyKey, "key", "k", "",
		"Public key PEM file (RSA or ECDSA)")
	_ = verifyCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(_ *cobra.Command, _ []string) error {
	// Read data.
	var data []byte
	switch {
	case verifyInput != "":
		data = []byte(verifyInput)
	case verifyFile != "":
		var err error
		data, err = os.ReadFile(verifyFile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", verifyFile, err)
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

	// Read signature.
	var sig []byte
	switch {
	case verifySig != "":
		var err error
		sig, err = os.ReadFile(verifySig)
		if err != nil {
			return fmt.Errorf("reading signature file %s: %w", verifySig, err)
		}
	case verifySigHex != "":
		var err error
		sig, err = hex.DecodeString(strings.TrimSpace(verifySigHex))
		if err != nil {
			return fmt.Errorf("decoding hex signature: %w", err)
		}
	default:
		return fmt.Errorf("no signature specified — use --sig or --sig-hex")
	}

	kt, _ := sign.KeyType(verifyKey)
	fmt.Fprintf(os.Stderr, "Key type: %s\n", kt)

	if err := sign.Verify(data, sig, verifyKey); err != nil {
		die("Verification FAILED: %v", err)
		return nil // unreachable; die exits
	}
	success("Signature is VALID ✓")
	return nil
}
