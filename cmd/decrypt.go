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

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt text, files, directories, or stdin",
	Long: `Decrypt data previously encrypted with GoCryptic.

The algorithm is auto-detected from the packet header unless --algo rsa is
specified (RSA requires a private key and cannot be auto-detected).

EXAMPLES:
  # Decrypt a base64 string from stdout
  gocryptic decrypt --input "<base64>" --key mypassword

  # Decrypt a file; output goes to notes.txt (strips .gcry)
  gocryptic decrypt --file notes.txt.gcry --key mypassword

  # Decrypt with RSA private key
  gocryptic decrypt --algo rsa --file data.enc --rsa-key priv.pem --output data.bin

  # Decrypt every .gcry file in a directory
  gocryptic decrypt --dir ./vault --key mypassword

  # Decrypt from stdin
  cat secret.gcry | gocryptic decrypt --key mypassword`,
	RunE: runDecrypt,
}

var (
	dAlgo    string
	dInput   string
	dFile    string
	dDir     string
	dKey     string
	dKeyEnv  string
	dKeyFile string
	dPrompt  bool
	dRSAKey  string
	dOut     string
	dRaw     bool
)

func init() {
	decryptCmd.Flags().StringVarP(&dAlgo, "algo", "a", "auto",
		"Algorithm: auto | aes-gcm | aes-cbc | chacha20 | rsa")
	decryptCmd.Flags().StringVarP(&dInput, "input", "i", "",
		"Base64-encoded ciphertext string to decrypt")
	decryptCmd.Flags().StringVarP(&dFile, "file", "f", "",
		"Encrypted file to decrypt")
	decryptCmd.Flags().StringVarP(&dDir, "dir", "d", "",
		"Directory of .gcry files to decrypt recursively")
	decryptCmd.Flags().StringVarP(&dKey, "key", "k", "",
		"Password used during encryption")
	decryptCmd.Flags().StringVar(&dKeyEnv, "key-env", "",
		"Environment variable containing the password (e.g. --key-env GCRY_PASS)")
	decryptCmd.Flags().StringVar(&dKeyFile, "key-file", "",
		"File containing the password (first line is used)")
	decryptCmd.Flags().BoolVarP(&dPrompt, "prompt", "p", false,
		"Prompt for password interactively (input hidden, like sudo)")
	decryptCmd.Flags().StringVar(&dRSAKey, "rsa-key", "",
		"RSA private key PEM file (required when --algo rsa)")
	decryptCmd.Flags().StringVarP(&dOut, "output", "o", "",
		"Output file (default: strips .gcry suffix, or stdout for string/stdin mode)")
	decryptCmd.Flags().BoolVar(&dRaw, "raw", false,
		"Treat --input as raw binary (hex or raw bytes) instead of base64")
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(_ *cobra.Command, _ []string) error {
	algo := strings.ToLower(dAlgo)

	sources := 0
	if dInput != "" {
		sources++
	}
	if dFile != "" {
		sources++
	}
	if dDir != "" {
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

	if algo == "rsa" && dRSAKey == "" {
		return fmt.Errorf("--rsa-key (RSA private key PEM) is required for RSA decryption")
	}
	if algo != "rsa" {
		var err error
		dKey, err = resolveKey(dKey, dKeyEnv, dKeyFile, dPrompt)
		if err != nil {
			return err
		}
	}

	if dDir != "" {
		return decryptDirectory(dDir, algo)
	}

	ct, err := readCiphertext(dInput, dFile, dRaw)
	if err != nil {
		return err
	}

	pt, err := decryptBytes(ct, algo)
	if err != nil {
		return err
	}

	return writeDecryptedOutput(pt, dFile, dOut)
}

// decryptBytes dispatches to the correct algorithm.
func decryptBytes(ct []byte, algo string) ([]byte, error) {
	switch algo {
	case "auto", "":
		if dKey == "" {
			return nil, fmt.Errorf("--key is required for auto-detect decryption")
		}
		return crypto.DecryptAuto(ct, dKey)
	case "aes-gcm":
		return crypto.DecryptAESGCM(ct, dKey)
	case "aes-cbc":
		return crypto.DecryptAESCBC(ct, dKey)
	case "chacha20":
		return crypto.DecryptChaCha20(ct, dKey)
	case "rsa":
		return crypto.DecryptRSA(ct, dRSAKey)
	default:
		return nil, fmt.Errorf("unknown algorithm %q  (choices: auto, aes-gcm, aes-cbc, chacha20, rsa)", algo)
	}
}

// readCiphertext reads ciphertext from a base64 string, file, or stdin.
func readCiphertext(inputStr, filePath string, raw bool) ([]byte, error) {
	switch {
	case inputStr != "":
		if raw {
			return []byte(inputStr), nil
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(inputStr))
	case filePath != "":
		return os.ReadFile(filePath)
	default:
		return io.ReadAll(os.Stdin)
	}
}

// writeDecryptedOutput writes plaintext to a file or stdout.
func writeDecryptedOutput(pt []byte, srcFile, outFile string) error {
	// Derive default output path by stripping .gcry extension.
	if srcFile != "" && outFile == "" {
		if strings.HasSuffix(srcFile, ".gcry") {
			outFile = strings.TrimSuffix(srcFile, ".gcry")
		} else {
			outFile = srcFile + ".dec"
		}
	}
	if outFile != "" {
		if err := os.WriteFile(outFile, pt, 0644); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
		success("Decrypted → %s  (%d bytes)", outFile, len(pt))
		return nil
	}
	_, err := os.Stdout.Write(pt)
	return err
}

// decryptDirectory walks dir, decrypts every .gcry file, and removes it.
func decryptDirectory(dir, algo string) error {
	fmt.Fprintf(os.Stderr, "Decrypting directory: %s\n\n", dir)
	count := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".gcry") {
			return nil
		}
		ct, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		pt, err := decryptBytes(ct, algo)
		if err != nil {
			return fmt.Errorf("decrypting %s: %w", path, err)
		}
		out := strings.TrimSuffix(path, ".gcry")
		if err := os.WriteFile(out, pt, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", out, err)
		}
		if err := os.Remove(path); err != nil {
			warn("Could not remove encrypted file %s: %v", path, err)
		}
		success("%s", out)
		count++
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%d file(s) decrypted.\n", count)
	return nil
}