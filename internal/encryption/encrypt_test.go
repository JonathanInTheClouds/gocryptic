package encryption_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JonathanInTheClouds/gocryptic/internal/encryption"
)

func TestEncryptDecryptFile(t *testing.T) {
	originalContent := "This is the content of the file"
	key := "fileencryptionkey"

	// Create a temporary file for testing
	inputFile, err := os.CreateTemp("", "testfile.txt") // Use os.CreateTemp instead of ioutil.TempFile
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(inputFile.Name()) // Clean up file after test

	// Write original content to the temp file
	if _, err := inputFile.Write([]byte(originalContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	// Create temp files for encrypted and decrypted output
	encryptedFile, err := os.CreateTemp("", "encryptedfile.enc") // Use os.CreateTemp
	if err != nil {
		t.Fatalf("Failed to create temp file for encryption: %v", err)
	}
	defer os.Remove(encryptedFile.Name())

	decryptedFile, err := os.CreateTemp("", "decryptedfile.txt") // Use os.CreateTemp
	if err != nil {
		t.Fatalf("Failed to create temp file for decryption: %v", err)
	}
	defer os.Remove(decryptedFile.Name())

	// Encrypt the file
	if err := encryption.EncryptFile(inputFile.Name(), encryptedFile.Name(), key); err != nil {
		t.Fatalf("File encryption failed: %v", err)
	}

	// Decrypt the encrypted file
	if err := encryption.DecryptFile(encryptedFile.Name(), decryptedFile.Name(), key); err != nil {
		t.Fatalf("File decryption failed: %v", err)
	}

	// Read the decrypted content using os.ReadFile
	decryptedContent, err := os.ReadFile(decryptedFile.Name()) // Use os.ReadFile instead of ioutil.ReadFile
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	// Check if the decrypted content matches the original
	if string(decryptedContent) != originalContent {
		t.Errorf("Decrypted file content doesn't match original. Got: %v, Want: %v", string(decryptedContent), originalContent)
	}
}

func TestEncryptDecryptDirectory(t *testing.T) {
	key := "directoryencryptionkey"

	// Create temporary directories for input, encrypted, and decrypted content
	inputDir, err := os.MkdirTemp("", "inputdir")
	if err != nil {
		t.Fatalf("Failed to create temp input directory: %v", err)
	}
	defer os.RemoveAll(inputDir)

	encryptedDir, err := os.MkdirTemp("", "encrypteddir")
	if err != nil {
		t.Fatalf("Failed to create temp encrypted directory: %v", err)
	}
	defer os.RemoveAll(encryptedDir)

	decryptedDir, err := os.MkdirTemp("", "decrypteddir")
	if err != nil {
		t.Fatalf("Failed to create temp decrypted directory: %v", err)
	}
	defer os.RemoveAll(decryptedDir)

	// Create test files in the input directory using os.WriteFile instead of ioutil.WriteFile
	file1Content := "File 1 content"
	file2Content := "File 2 content"

	os.WriteFile(filepath.Join(inputDir, "file1.txt"), []byte(file1Content), 0644)
	os.WriteFile(filepath.Join(inputDir, "file2.txt"), []byte(file2Content), 0644)

	// Encrypt the directory
	if err := encryption.EncryptDirectory(inputDir, encryptedDir, key); err != nil {
		t.Fatalf("Directory encryption failed: %v", err)
	}

	// Decrypt the directory
	if err := encryption.DecryptDirectory(encryptedDir, decryptedDir, key); err != nil {
		t.Fatalf("Directory decryption failed: %v", err)
	}

	// Check if the decrypted files exist and their content matches
	decryptedFile1, err := os.ReadFile(filepath.Join(decryptedDir, "file1.txt.dec")) // Use os.ReadFile
	if err != nil {
		t.Fatalf("Failed to read decrypted file1: %v", err)
	}

	decryptedFile2, err := os.ReadFile(filepath.Join(decryptedDir, "file2.txt.dec")) // Use os.ReadFile
	if err != nil {
		t.Fatalf("Failed to read decrypted file2: %v", err)
	}

	// Compare contents
	if string(decryptedFile1) != file1Content {
		t.Errorf("Decrypted file1 content doesn't match. Got: %v, Want: %v", string(decryptedFile1), file1Content)
	}

	if string(decryptedFile2) != file2Content {
		t.Errorf("Decrypted file2 content doesn't match. Got: %v, Want: %v", string(decryptedFile2), file2Content)
	}
}
