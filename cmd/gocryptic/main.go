package main

import (
	"fmt"
	"os"

	"github.com/JonathanInTheClouds/gocryptic/internal/encryption"
	"github.com/spf13/cobra"
)

var key string
var input string
var output string

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gocryptic",
		Short: "GoCryptic: A simple encryption/decryption tool",
	}

	var encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a file, folder, or plaintext",
		Run: func(cmd *cobra.Command, args []string) {
			if input == "" || output == "" || key == "" {
				fmt.Println("Please provide input, output, and key")
				return
			}

			fileInfo, err := os.Stat(input)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			if fileInfo.IsDir() {
				// Encrypt the entire directory
				err := encryption.EncryptDirectory(input, output, key)
				if err != nil {
					fmt.Printf("Error encrypting directory: %v\n", err)
				} else {
					fmt.Println("Directory encryption successful")
				}
			} else {
				// Encrypt a single file
				err := encryption.EncryptFile(input, output, key)
				if err != nil {
					fmt.Printf("Error encrypting file: %v\n", err)
				} else {
					fmt.Println("File encryption successful")
				}
			}
		},
	}

	var decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a file, folder, or ciphertext",
		Run: func(cmd *cobra.Command, args []string) {
			if input == "" || output == "" || key == "" {
				fmt.Println("Please provide input, output, and key")
				return
			}

			fileInfo, err := os.Stat(input)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}

			if fileInfo.IsDir() {
				// Decrypt the entire directory
				err := encryption.DecryptDirectory(input, output, key)
				if err != nil {
					fmt.Printf("Error decrypting directory: %v\n", err)
				} else {
					fmt.Println("Directory decryption successful")
				}
			} else {
				// Decrypt a single file
				err := encryption.DecryptFile(input, output, key)
				if err != nil {
					fmt.Printf("Error decrypting file: %v\n", err)
				} else {
					fmt.Println("File decryption successful")
				}
			}
		},
	}

	encryptCmd.Flags().StringVarP(&key, "key", "k", "", "Encryption key")
	encryptCmd.Flags().StringVarP(&input, "input", "i", "", "Input file or directory")
	encryptCmd.Flags().StringVarP(&output, "output", "o", "", "Output file or directory")

	decryptCmd.Flags().StringVarP(&key, "key", "k", "", "Decryption key")
	decryptCmd.Flags().StringVarP(&input, "input", "i", "", "Input file or directory")
	decryptCmd.Flags().StringVarP(&output, "output", "o", "", "Output file or directory")

	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	rootCmd.Execute()
}
