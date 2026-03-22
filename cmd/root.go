// Package cmd implements the GoCryptic command-line interface.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

// SetVersion is called from main with the build-time version string.
func SetVersion(v string) { version = v }

var rootCmd = &cobra.Command{
	Use:     "gocryptic",
	Version: version,
	Short: "GoCryptic — A powerful cryptographic toolkit",
	Long: `
  ██████╗  ██████╗  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ ██████╗
 ██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔════╝
 ██║  ███╗██║   ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║
 ██║   ██║██║   ██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║
 ╚██████╔╝╚██████╔╝╚██████╗██║  ██║   ██║   ██║        ██║   ██║╚██████╗
  ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝ ╚═════╝

GoCryptic is a feature-rich cryptographic CLI toolkit written in Go.

COMMANDS:
  encrypt   Encrypt text, files, directories, or stdin
  decrypt   Decrypt text, files, directories, or stdin
  hash      Compute cryptographic hashes (MD5 → SHA3-512)
  keygen    Generate AES / ChaCha20 / RSA / ECDSA keys and passwords
  encode    Base64 and Hex encode / decode
  sign      Sign data with an RSA or ECDSA private key
  verify    Verify a digital signature

Run "gocryptic <command> --help" for detailed usage and examples.`,
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
