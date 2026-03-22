package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gocryptic/gocryptic/internal/crypto"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt text, files, directories, or stdin",
	Long: `Encrypt data using AES-256-GCM, AES-256-CBC, XChaCha20-Poly1305, or RSA (hybrid).

Symmetric algorithms (aes-gcm, aes-cbc, chacha20) derive keys from a password
using scrypt.  RSA uses hybrid encryption: a random AES-256-GCM session key is
wrapped with RSA-OAEP and stored alongside the ciphertext, so there is no file
size limit.

EXAMPLES:
  # Encrypt a string (outputs base64 to stdout)
  gocryptic encrypt --algo aes-gcm --input "top secret" --key mypassword

  # Encrypt a file; output goes to notes.txt.gcry
  gocryptic encrypt --algo chacha20 --file notes.txt --key mypassword

  # Encrypt with RSA public key (hybrid mode)
  gocryptic encrypt --algo rsa --file data.bin --rsa-key pub.pem --output data.enc

  # Encrypt every file in a directory (skips .gcry files)
  gocryptic encrypt --algo aes-gcm --dir ./vault --key mypassword

  # Encrypt stdin
  echo "hello world" | gocryptic encrypt --algo aes-gcm --key mypassword`,
	RunE: runEncrypt,
}

var (
	eAlgo    string
	eInput   string
	eFile    string
	eDir     string
	eKey     string
	eKeyEnv  string
	eKeyFile string
	ePrompt  bool
	eConfirm bool
	eRSAKey  string
	eOut     string
	eRaw     bool
)

func init() {
	encryptCmd.Flags().StringVarP(&eAlgo, "algo", "a", "aes-gcm",
		"Algorithm: aes-gcm | aes-cbc | chacha20 | rsa")
	encryptCmd.Flags().StringVarP(&eInput, "input", "i", "",
		"Plaintext string to encrypt")
	encryptCmd.Flags().StringVarP(&eFile, "file", "f", "",
		"File to encrypt")
	encryptCmd.Flags().StringVarP(&eDir, "dir", "d", "",
		"Directory to encrypt recursively")
	encryptCmd.Flags().StringVarP(&eKey, "key", "k", "",
		"Password for symmetric encryption")
	encryptCmd.Flags().StringVar(&eKeyEnv, "key-env", "",
		"Environment variable containing the password (e.g. --key-env GCRY_PASS)")
	encryptCmd.Flags().StringVar(&eKeyFile, "key-file", "",
		"File containing the password (first line is used)")
	encryptCmd.Flags().BoolVarP(&ePrompt, "prompt", "p", false,
		"Prompt for password interactively (input hidden, like sudo)")
	encryptCmd.Flags().BoolVarP(&eConfirm, "confirm", "c", false,
		"Ask for password twice to confirm (use with --prompt)")
	encryptCmd.Flags().StringVar(&eRSAKey, "rsa-key", "",
		"RSA public key PEM file (required when --algo rsa)")
	encryptCmd.Flags().StringVarP(&eOut, "output", "o", "",
		"Output file (default: <input-file>.gcry, or stdout for --input/stdin)")
	encryptCmd.Flags().BoolVar(&eRaw, "raw", false,
		"Write raw bytes to stdout instead of base64 (for --input / stdin mode)")
	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(_ *cobra.Command, _ []string) error {
	algo := strings.ToLower(eAlgo)

	// Validate mutually-exclusive input sources.
	sources := 0
	if eInput != "" {
		sources++
	}
	if eFile != "" {
		sources++
	}
	if eDir != "" {
		sources++
	}
	if isStdin() {
		sources++
	}
	if sources == 0 {
		return fmt.Errorf("no input specified — use --input, --file, --dir, or pipe to stdin")
	}
	if sources > 1 {
		return fmt.Errorf("only one input source is allowed at a time")
	}

	// Key validation.
	if algo != "rsa" {
		var err error
		if ePrompt && eConfirm {
			eKey, err = promptPasswordConfirm()
			if err != nil {
				return err
			}
		} else {
			eKey, err = resolveKey(eKey, eKeyEnv, eKeyFile, ePrompt)
			if err != nil {
				return err
			}
		}
	}
	if algo == "rsa" && eRSAKey == "" {
		return fmt.Errorf("--rsa-key (RSA public key PEM) is required for RSA encryption")
	}

	// Directory mode.
	if eDir != "" {
		return encryptDirectory(eDir, algo)
	}

	// Single-item mode: read plaintext.
	plaintext, err := readInput(eInput, eFile)
	if err != nil {
		return err
	}

	ct, err := encryptBytes(plaintext, algo)
	if err != nil {
		return err
	}

	return writeEncryptedOutput(ct, eFile, eOut, eRaw)
}

// encryptBytes dispatches to the correct algorithm implementation.
func encryptBytes(plaintext []byte, algo string) ([]byte, error) {
	switch algo {
	case "aes-gcm":
		return crypto.EncryptAESGCM(plaintext, eKey)
	case "aes-cbc":
		return crypto.EncryptAESCBC(plaintext, eKey)
	case "chacha20":
		return crypto.EncryptChaCha20(plaintext, eKey)
	case "rsa":
		return crypto.EncryptRSA(plaintext, eRSAKey)
	default:
		return nil, fmt.Errorf("unknown algorithm %q  (choices: aes-gcm, aes-cbc, chacha20, rsa)", algo)
	}
}

// readInput reads plaintext from the specified source (string, file, or stdin).
func readInput(inputStr, filePath string) ([]byte, error) {
	switch {
	case inputStr != "":
		return []byte(inputStr), nil
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", filePath, err)
		}
		return data, nil
	default:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return data, nil
	}
}

// writeEncryptedOutput writes ciphertext to a file or stdout.
func writeEncryptedOutput(ct []byte, srcFile, outFile string, raw bool) error {
	// Derive default output path from source file name.
	if srcFile != "" && outFile == "" {
		outFile = srcFile + ".gcry"
	}
	if outFile != "" {
		if err := os.WriteFile(outFile, ct, 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		success("Encrypted → %s  (%d bytes)", outFile, len(ct))
		return nil
	}
	// stdout: base64 by default for readability; raw binary if --raw.
	if raw {
		_, err := os.Stdout.Write(ct)
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ct))
	return nil
}

// encryptDirectory walks dir and encrypts every non-.gcry file in-place.
func encryptDirectory(dir, algo string) error {
	if algo == "rsa" {
		return fmt.Errorf("RSA is not supported for directory encryption — use aes-gcm, aes-cbc, or chacha20")
	}
	fmt.Fprintf(os.Stderr, "Encrypting directory: %s  (algo=%s)\n\n", dir, algo)
	count := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || strings.HasSuffix(path, ".gcry") {
			return nil // skip directories and already-encrypted files
		}

		pt, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		ct, err := encryptBytes(pt, algo)
		if err != nil {
			return fmt.Errorf("encrypting %s: %w", path, err)
		}
		out := path + ".gcry"
		if err := os.WriteFile(out, ct, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", out, err)
		}
		if err := os.Remove(path); err != nil {
			warn("Could not remove original file %s: %v", path, err)
		}
		success("%s", out)
		count++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%d file(s) encrypted.\n", count)
	return nil
}