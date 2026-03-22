package cmd

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// resolveKey returns the encryption password from the first available source:
//  1. --key       direct value on the command line
//  2. --key-env   name of an environment variable holding the password
//  3. --key-file  path to a file whose first line is the password
//  4. --prompt    interactive hidden input (like sudo)
//
// Returns an error if none are set or if the resolved value is empty.
func resolveKey(key, keyEnv, keyFile string, prompt bool) (string, error) {
	if key != "" {
		return key, nil
	}
	if keyEnv != "" {
		val := os.Getenv(keyEnv)
		if val == "" {
			return "", fmt.Errorf("environment variable %q is not set or is empty", keyEnv)
		}
		return val, nil
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("reading key file %q: %w", keyFile, err)
		}
		val := strings.TrimRight(string(data), "\r\n")
		if val == "" {
			return "", fmt.Errorf("key file %q is empty", keyFile)
		}
		return val, nil
	}
	if prompt {
		return promptPassword()
	}
	return "", fmt.Errorf("no key provided — use --key, --key-env, --key-file, or --prompt")
}

// promptPassword reads a password from the terminal with echo disabled.
// The typed characters are invisible, exactly like sudo.
func promptPassword() (string, error) {
	return readHidden("Password: ")
}

// promptPasswordConfirm reads a password twice and errors if they don't match.
// Used during encryption so the user doesn't lock themselves out with a typo.
func promptPasswordConfirm() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("--prompt requires an interactive terminal (stdin is a pipe)")
	}
	first, err := readHidden("Password: ")
	if err != nil {
		return "", err
	}
	second, err := readHidden("Confirm password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	return first, nil
}

// readHidden prints a label to stderr and reads a hidden line from the terminal.
func readHidden(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("--prompt requires an interactive terminal (stdin is a pipe)")
	}
	fmt.Fprint(os.Stderr, label)
	raw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	return string(raw), nil
}