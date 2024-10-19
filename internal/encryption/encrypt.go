package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// HashKey creates a 32-byte hash key from the user-provided key
func HashKey(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// Encrypt encrypts plaintext using AES encryption with a provided key
func Encrypt(plaintext, key string) (string, error) {
	hashedKey := HashKey(key)

	block, err := aes.NewCipher(hashedKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())

	// Seal encrypts and appends the ciphertext to the nonce.
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil) // []byte for plaintext
	return hex.EncodeToString(ciphertext), nil                      // Return hex-encoded string
}

// Decrypt decrypts the encrypted text using AES with the provided key
func Decrypt(ciphertext, key string) (string, error) {
	hashedKey := HashKey(key)

	encryptedData, err := hex.DecodeString(ciphertext) // Decode from hex string to []byte
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(hashedKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := encryptedData[:nonceSize], encryptedData[nonceSize:] // Use []byte instead of string

	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil // Return as string since plaintext can be a human-readable string
}

// EncryptFile encrypts a file and saves the encrypted version to the output path
func EncryptFile(inputPath, outputPath, key string) error {
	content, err := os.ReadFile(inputPath) // Use os.ReadFile instead of ioutil.ReadFile
	if err != nil {
		return err
	}

	encrypted, err := Encrypt(string(content), key)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, []byte(encrypted), 0644) // Use os.WriteFile instead of ioutil.WriteFile
}

// DecryptFile decrypts a file and saves the decrypted version to the output path
func DecryptFile(inputPath, outputPath, key string) error {
	// Read the file contents
	content, err := os.ReadFile(inputPath) // Use os.ReadFile instead of ioutil.ReadFile
	if err != nil {
		return err
	}

	// Decrypt the file contents
	decrypted, err := Decrypt(string(content), key)
	if err != nil {
		return err
	}

	// Write the decrypted content back to the output file
	return os.WriteFile(outputPath, []byte(decrypted), 0644) // Use os.WriteFile instead of ioutil.WriteFile
}

// EncryptDirectory encrypts all files in a directory
func EncryptDirectory(inputDir, outputDir, key string) error {
	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Get the relative path to maintain the directory structure
			relativePath, _ := filepath.Rel(inputDir, path)
			outputPath := filepath.Join(outputDir, relativePath+".enc")

			// Ensure the directory structure is created in the output directory
			outputDirPath := filepath.Dir(outputPath)
			if err := os.MkdirAll(outputDirPath, os.ModePerm); err != nil {
				return err
			}

			// Encrypt the file
			return EncryptFile(path, outputPath, key)
		}
		return nil
	})
}

// DecryptDirectory decrypts all files in a directory
func DecryptDirectory(inputDir, outputDir, key string) error {
	return filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Remove the .enc extension from the filename before adding .dec
			relativePath, _ := filepath.Rel(inputDir, path)
			if filepath.Ext(relativePath) == ".enc" {
				relativePath = relativePath[:len(relativePath)-4] // Remove ".enc"
			}
			outputPath := filepath.Join(outputDir, relativePath+".dec") // Add ".dec" extension

			// Ensure the output directory structure exists
			outputDirPath := filepath.Dir(outputPath)
			if err := os.MkdirAll(outputDirPath, os.ModePerm); err != nil {
				return err
			}

			// Decrypt the file
			return DecryptFile(path, outputPath, key)
		}
		return nil
	})
}
