package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveKeyDirect covers --key (plain value).
func TestResolveKeyDirect(t *testing.T) {
	got, err := resolveKey("secret", "", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("want 'secret', got %q", got)
	}
}

// TestResolveKeyEnv covers --key-env.
func TestResolveKeyEnv(t *testing.T) {
	t.Setenv("GCRY_TEST_PASS", "envpassword")

	got, err := resolveKey("", "GCRY_TEST_PASS", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "envpassword" {
		t.Fatalf("want 'envpassword', got %q", got)
	}
}

// TestResolveKeyEnvUnset errors when the named variable is not set.
func TestResolveKeyEnvUnset(t *testing.T) {
	os.Unsetenv("GCRY_NOTSET")
	if _, err := resolveKey("", "GCRY_NOTSET", "", false); err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
}

// TestResolveKeyFile covers --key-file.
func TestResolveKeyFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keyfile.txt")
	if err := os.WriteFile(f, []byte("filepassword\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveKey("", "", f, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "filepassword" {
		t.Fatalf("want 'filepassword', got %q", got)
	}
}

// TestResolveKeyFileStripsNewlines ensures CRLF and LF are trimmed.
func TestResolveKeyFileStripsNewlines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keyfile.txt")
	if err := os.WriteFile(f, []byte("trimmed\r\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveKey("", "", f, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "trimmed" {
		t.Fatalf("want 'trimmed', got %q", got)
	}
}

// TestResolveKeyFileEmpty errors on an empty key file.
func TestResolveKeyFileEmpty(t *testing.T) {
	f := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(f, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveKey("", "", f, false); err == nil {
		t.Fatal("expected error for empty key file, got nil")
	}
}

// TestResolveKeyFileMissing errors when the file doesn't exist.
func TestResolveKeyFileMissing(t *testing.T) {
	if _, err := resolveKey("", "", "/nonexistent/path/key.txt", false); err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

// TestResolveKeyNoneProvided errors when no source is given and prompt=false.
func TestResolveKeyNoneProvided(t *testing.T) {
	if _, err := resolveKey("", "", "", false); err == nil {
		t.Fatal("expected error when no key source provided, got nil")
	}
}

// TestResolveKeyDirectTakesPrecedence verifies --key wins over --key-env.
func TestResolveKeyDirectTakesPrecedence(t *testing.T) {
	t.Setenv("GCRY_TEST_PASS", "envpassword")

	got, err := resolveKey("directwin", "GCRY_TEST_PASS", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "directwin" {
		t.Fatalf("--key should take precedence, got %q", got)
	}
}

// TestResolveKeyEnvTakesPrecedenceOverFile verifies --key-env wins over --key-file.
func TestResolveKeyEnvTakesPrecedenceOverFile(t *testing.T) {
	t.Setenv("GCRY_TEST_PASS", "envwins")

	f := filepath.Join(t.TempDir(), "keyfile.txt")
	if err := os.WriteFile(f, []byte("filepassword\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveKey("", "GCRY_TEST_PASS", f, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "envwins" {
		t.Fatalf("--key-env should take precedence over --key-file, got %q", got)
	}
}

// TestPromptNonTTY verifies --prompt fails gracefully when stdin is not a terminal
// (which is always the case in automated tests — stdin is a pipe).
func TestPromptNonTTY(t *testing.T) {
	if _, err := resolveKey("", "", "", true); err == nil {
		t.Fatal("expected error when --prompt used in non-TTY context, got nil")
	}
}
