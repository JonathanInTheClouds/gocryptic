# GoCryptic

GoCryptic is a simple command-line encryption and decryption tool written in Golang. It allows you to encrypt and decrypt plaintext, files, and directories using a user-provided key. It uses AES encryption for secure file and text encryption.

## Features

- **Encrypt/Decrypt Plaintext**: Encrypt a plain string and decrypt it back using a provided key.
- **Encrypt/Decrypt Files**: Encrypt or decrypt an entire file using a secret key.
- **Encrypt/Decrypt Folders**: Encrypt or decrypt all files in a directory.
- **Key Management**: Provide a user-defined key to secure your data.
- **Cross-Platform**: Works on all platforms that support Go.

## Prerequisites

You need to have Golang installed on your machine. You can download it from [here](https://golang.org/dl/).

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/JonathanInTheClouds/gocryptic.git
   ```

2. Navigate to the project directory:

   ```bash
   cd gocryptic
   ```

3. Install the dependencies:

   ```bash
   go mod tidy
   ```

4. Build the CLI application:

   ```bash
   go build -o gocryptic cmd/gocryptic/main.go
   ```

## Usage

### Encrypt a File

```bash
./gocryptic encrypt --input <file> --output <encrypted-file> --key <your-key>
```

For example:

```bash
./gocryptic encrypt --input example.txt --output example.enc --key mysecretkey
```

### Decrypt a File

```bash
./gocryptic decrypt --input <encrypted-file> --output <decrypted-file> --key <your-key>
```

For example:

```bash
./gocryptic decrypt --input example.enc --output example.txt --key mysecretkey
```

### Encrypt a Directory

```bash
./gocryptic encrypt --input <directory> --output <output-directory> --key <your-key>
```

### Decrypt a Directory

```bash
./gocryptic decrypt --input <directory> --output <output-directory> --key <your-key>
```

## Running Tests

To run unit tests for the encryption and decryption functions:

```bash
go test ./test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
