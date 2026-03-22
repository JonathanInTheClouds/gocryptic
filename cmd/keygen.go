package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gocryptic/gocryptic/internal/keygen"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate AES / ChaCha20 / RSA / ECDSA keys and passwords",
	Long: `Generate cryptographically secure keys and passwords.

KEY TYPES:
  aes       Random AES key (128, 192, or 256 bits), printed as hex
  chacha20  Random 256-bit XChaCha20-Poly1305 key, printed as hex
  rsa       RSA key pair written to PEM files (default 4096 bits)
  ecdsa     ECDSA P-256 key pair written to PEM files
  password  Random printable password

EXAMPLES:
  # Generate a 256-bit AES key
  gocryptic keygen --type aes --bits 256

  # Generate a ChaCha20 key
  gocryptic keygen --type chacha20

  # Generate a 4096-bit RSA key pair
  gocryptic keygen --type rsa --bits 4096 --priv priv.pem --pub pub.pem

  # Generate an ECDSA P-256 key pair
  gocryptic keygen --type ecdsa --priv ec_priv.pem --pub ec_pub.pem

  # Generate a 32-char password with special chars
  gocryptic keygen --type password --length 32 --special`,
	RunE: runKeygen,
}

var (
	kType    string
	kBits    int
	kPriv    string
	kPub     string
	kLength  int
	kSpecial bool
)

func init() {
	keygenCmd.Flags().StringVarP(&kType, "type", "t", "aes",
		"Key type: aes | chacha20 | rsa | ecdsa | password")
	keygenCmd.Flags().IntVar(&kBits, "bits", 256,
		"Key size in bits (AES: 128/192/256; RSA: ≥2048; ignored for others)")
	keygenCmd.Flags().StringVar(&kPriv, "priv", "priv.pem",
		"Output path for RSA/ECDSA private key PEM")
	keygenCmd.Flags().StringVar(&kPub, "pub", "pub.pem",
		"Output path for RSA/ECDSA public key PEM")
	keygenCmd.Flags().IntVarP(&kLength, "length", "l", 24,
		"Password length (for --type password)")
	keygenCmd.Flags().BoolVar(&kSpecial, "special", false,
		"Include special characters in generated password")
	rootCmd.AddCommand(keygenCmd)
}

func runKeygen(_ *cobra.Command, _ []string) error {
	switch strings.ToLower(kType) {
	case "aes":
		key, err := keygen.GenerateAESKey(kBits)
		if err != nil {
			return err
		}
		fmt.Printf("AES-%d key (hex):\n%s\n", kBits, hex.EncodeToString(key))

	case "chacha20":
		key, err := keygen.GenerateChaChaKey()
		if err != nil {
			return err
		}
		fmt.Printf("XChaCha20-Poly1305 key (hex):\n%s\n", hex.EncodeToString(key))

	case "rsa":
		fmt.Printf("Generating RSA-%d key pair…\n", kBits)
		if err := keygen.GenerateRSAKeyPair(kBits, kPriv, kPub); err != nil {
			return err
		}
		success("Private key → %s  (mode 0600)", kPriv)
		success("Public key  → %s  (mode 0644)", kPub)

	case "ecdsa", "ecdh":
		fmt.Printf("Generating ECDSA/ECDH P-256 key pair…\n")
		if err := keygen.GenerateECDSAKeyPair(kPriv, kPub); err != nil {
			return err
		}
		success("Private key → %s  (mode 0600)", kPriv)
		success("Public key  → %s  (mode 0644)", kPub)

	case "password":
		pw, err := keygen.GeneratePassword(kLength, kSpecial)
		if err != nil {
			return err
		}
		fmt.Printf("Generated password (%d chars):\n%s\n", kLength, pw)

	default:
		return fmt.Errorf("unknown key type %q  (choices: aes, chacha20, rsa, ecdsa, password)", kType)
	}
	return nil
}
