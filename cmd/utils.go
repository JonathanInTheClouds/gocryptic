package cmd

import (
	"fmt"
	"os"
)

// isStdin returns true when stdin is a pipe or redirect (not an interactive terminal).
func isStdin() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// success prints a green ✓ status line to stderr.
func success(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  \033[32m✓\033[0m "+format+"\n", args...)
}

// warn prints a yellow ⚠ warning line to stderr.
func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  \033[33m⚠\033[0m "+format+"\n", args...)
}

// die prints a red ✗ error line to stderr and exits with code 1.
func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "  \033[31m✗\033[0m "+format+"\n", args...)
	os.Exit(1)
}
