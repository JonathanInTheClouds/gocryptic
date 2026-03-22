package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gocryptic/gocryptic/internal/hash"
	"github.com/spf13/cobra"
)

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Compute cryptographic hashes",
	Long: `Compute cryptographic hashes of text, files, or stdin.

Supported algorithms: md5, sha1, sha256, sha384, sha512, sha3-256, sha3-512.
Use --algo all to compute all algorithms at once (great for comparisons).

EXAMPLES:
  # Hash a string with SHA-256
  gocryptic hash --input "hello world"

  # Hash a file with SHA-512
  gocryptic hash --algo sha512 --file archive.tar.gz

  # Show all hashes for a file
  gocryptic hash --algo all --file firmware.bin

  # Hash stdin
  cat myfile.txt | gocryptic hash --algo sha3-256`,
	RunE: runHash,
}

var (
	hAlgo  string
	hInput string
	hFile  string
)

func init() {
	hashCmd.Flags().StringVarP(&hAlgo, "algo", "a", "sha256",
		"Algorithm: md5|sha1|sha256|sha384|sha512|sha3-256|sha3-512|all")
	hashCmd.Flags().StringVarP(&hInput, "input", "i", "",
		"String to hash")
	hashCmd.Flags().StringVarP(&hFile, "file", "f", "",
		"File to hash")
	rootCmd.AddCommand(hashCmd)
}

func runHash(_ *cobra.Command, _ []string) error {
	algo := strings.ToLower(hAlgo)

	// Read data.
	var data []byte
	switch {
	case hInput != "":
		data = []byte(hInput)
	case hFile != "":
		// handled separately for streaming / all-at-once
	case isStdin():
		var err error
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading stdin: %w", err)
		}
	default:
		return fmt.Errorf("no input specified — use --input, --file, or pipe to stdin")
	}

	if algo == "all" {
		return printAllHashes(data, hFile)
	}
	return printSingleHash(data, hFile, algo)
}

func printSingleHash(data []byte, filePath, algo string) error {
	var digest string
	var err error
	if filePath != "" {
		digest, err = hash.SumFile(filePath, algo)
	} else {
		digest, err = hash.Sum(data, algo)
	}
	if err != nil {
		return err
	}
	label := filePath
	if label == "" {
		label = "(stdin)"
	}
	fmt.Printf("%s  %s  %s\n", strings.ToUpper(algo), digest, label)
	return nil
}

func printAllHashes(data []byte, filePath string) error {
	var results map[string]string
	var err error
	if filePath != "" {
		results, err = hash.SumFileAll(filePath)
		if err != nil {
			return err
		}
	} else {
		results = hash.SumAll(data)
	}

	label := filePath
	if label == "" {
		label = "(stdin / string)"
	}
	fmt.Fprintf(os.Stderr, "Hashes for: %s\n\n", label)

	tw := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
	for _, algo := range hash.Algorithms() {
		if d, ok := results[algo]; ok {
			fmt.Fprintf(tw, "%s\t%s\n", strings.ToUpper(algo), d)
		}
	}
	return tw.Flush()
}
