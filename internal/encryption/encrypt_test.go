package encryption_test

import (
	"testing"

	"github.com/JonathanInTheClouds/gocryptic/internal/encryption"
)

func TestEncryptionDecryption(t *testing.T) {
	plaintext := "Hello, GoCryptic!"
	key := "mysecretkey"

	encrypted, err := encryption.Encrypt(plaintext, key)
	if err != nil {
		t.Errorf("Error during encryption: %v", err)
	}

	decrypted, err := encryption.Decrypt(encrypted, key)
	if err != nil {
		t.Errorf("Error during decryption: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text does not match original: got %v, want %v", decrypted, plaintext)
	}
}
