# GoCryptic

**GoCryptic** is a feature-rich cryptographic CLI toolkit written in Go.  
It supports symmetric/asymmetric encryption, cryptographic hashing, key generation,  
Base64 & Hex encoding, and digital signatures — all from one binary.

---

## Features

| Category               | Capabilities                                                                  |
| ---------------------- | ----------------------------------------------------------------------------- |
| **Encryption**         | AES-256-GCM, AES-256-CBC (HMAC-SHA256), XChaCha20-Poly1305, RSA-OAEP (hybrid) |
| **Input sources**      | Strings, files, entire directories, stdin / pipes                             |
| **Hashing**            | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512                     |
| **Key generation**     | AES, ChaCha20, RSA (≥2048-bit), ECDSA P-256, secure passwords                 |
| **Encoding**           | Base64 (standard / URL-safe / raw), hexadecimal                               |
| **Digital signatures** | RSA-PSS (SHA-256), ECDSA P-256 — sign & verify                                |
| **Password input**     | `--key`, `--key-env`, `--key-file`, `--prompt` (hidden), `--confirm`          |
| **Security**           | scrypt KDF for all password-based encryption; HMAC-SHA256 auth on CBC mode    |

---

## Installation

### From source (requires Go 1.21+)

```bash
git clone https://github.com/gocryptic/gocryptic.git
cd gocryptic
go mod tidy
make build          # produces ./gocryptic
make install        # installs to $GOPATH/bin
```

### Cross-compile for all platforms

```bash
make cross-build    # outputs to ./dist/
```

---

## Quick Start

```bash
# Encrypt a string (password typed visibly)
gocryptic encrypt --algo aes-gcm --input 'top secret' --key mypassword

# Encrypt a file with a hidden password prompt (like sudo)
gocryptic encrypt --algo aes-gcm --file notes.txt --prompt

# Encrypt with confirmation — asks twice to prevent typos
gocryptic encrypt --algo aes-gcm --file notes.txt --prompt --confirm

# Decrypt
gocryptic decrypt --file notes.txt.gcry --prompt

# Hash a file
gocryptic hash --algo sha256 --file archive.tar.gz

# Show all hashes at once
gocryptic hash --algo all --file firmware.bin

# Generate a secure password
gocryptic keygen --type password --length 32 --special

# Generate an RSA key pair
gocryptic keygen --type rsa --bits 4096 --priv priv.pem --pub pub.pem

# Sign a file
gocryptic sign --file release.tar.gz --key priv.pem

# Verify a signature
gocryptic verify --file release.tar.gz --sig release.tar.gz.sig --key pub.pem
```

---

## Password Input

GoCryptic supports four ways to supply a password, evaluated in this order of precedence:

| Flag                | Description                        | Best for                 |
| ------------------- | ---------------------------------- | ------------------------ |
| `--key <value>`     | Plain text on the command line     | Quick local use          |
| `--key-env <VAR>`   | Read from an environment variable  | CI/CD pipelines, scripts |
| `--key-file <path>` | Read the first line of a file      | Automated deployments    |
| `--prompt` / `-p`   | Hidden interactive input (no echo) | Interactive use          |

### `--prompt` — hidden input

Behaves exactly like a `sudo` password prompt — characters are not echoed to the terminal.

```bash
gocryptic encrypt --algo aes-gcm --file secret.txt --prompt
# Password:
#   ✓ Encrypted → secret.txt.gcry
```

### `--confirm` / `-c` — confirmation on encrypt

Use together with `--prompt` to ask for the password twice and verify they match before encrypting. Prevents being locked out due to a typo.

```bash
gocryptic encrypt --algo aes-gcm --file secret.txt --prompt --confirm
# Password:
# Confirm password:
#   ✓ Encrypted → secret.txt.gcry
```

If the two entries don't match:

```
Password:
Confirm password:
  ✗ passwords do not match
```

### `--key-env` — environment variable

```bash
export GCRY_PASS='my secret password'
gocryptic encrypt --algo aes-gcm --file secret.txt --key-env GCRY_PASS
gocryptic decrypt --file secret.txt.gcry --key-env GCRY_PASS
```

The password never appears in shell history or `ps` output.

### `--key-file` — password file

```bash
echo 'my secret password' > .keyfile
chmod 600 .keyfile
gocryptic encrypt --algo aes-gcm --file secret.txt --key-file .keyfile
gocryptic decrypt --file secret.txt.gcry --key-file .keyfile
```

Only the first line of the file is used; trailing newlines are stripped.

---

## Commands

### `encrypt`

```
gocryptic encrypt [flags]

Flags:
  -a, --algo string      Algorithm: aes-gcm | aes-cbc | chacha20 | rsa  (default "aes-gcm")
  -i, --input string     Plaintext string to encrypt
  -f, --file string      File to encrypt
  -d, --dir string       Directory to encrypt recursively
  -k, --key string       Password (symmetric algorithms)
      --key-env string   Environment variable containing the password
      --key-file string  File containing the password (first line used)
  -p, --prompt           Prompt for password interactively (hidden input)
  -c, --confirm          Ask for password twice to confirm (use with --prompt)
      --rsa-key string   RSA public key PEM (--algo rsa)
  -o, --output string    Output file (default: <input>.gcry)
      --raw              Write raw bytes instead of base64 (stdout mode)
```

**Examples:**

```bash
# Encrypt a file with ChaCha20
gocryptic encrypt --algo chacha20 --file notes.txt --key s3cr3t

# Encrypt with hidden prompt and confirmation
gocryptic encrypt --algo aes-gcm --file notes.txt --prompt --confirm

# Encrypt with RSA
gocryptic encrypt --algo rsa --file data.bin --rsa-key pub.pem --output data.enc

# Encrypt every file in ./vault using an env var password
gocryptic encrypt --algo aes-gcm --dir ./vault --key-env GCRY_PASS

# Encrypt stdin
echo 'hello' | gocryptic encrypt --algo aes-cbc --key s3cr3t
```

---

### `decrypt`

```
gocryptic decrypt [flags]

Flags:
  -a, --algo string      Algorithm: auto | aes-gcm | aes-cbc | chacha20 | rsa  (default "auto")
  -i, --input string     Base64 ciphertext string to decrypt
  -f, --file string      Encrypted file (.gcry)
  -d, --dir string       Directory of .gcry files to decrypt
  -k, --key string       Password
      --key-env string   Environment variable containing the password
      --key-file string  File containing the password (first line used)
  -p, --prompt           Prompt for password interactively (hidden input)
      --rsa-key string   RSA private key PEM (--algo rsa)
  -o, --output string    Output file (default: strips .gcry suffix)
```

**`auto` mode** reads the 5-byte packet header to detect the algorithm automatically.

---

### `hash`

```
gocryptic hash [flags]

Flags:
  -a, --algo string    md5|sha1|sha256|sha384|sha512|sha3-256|sha3-512|all  (default "sha256")
  -i, --input string   String to hash
  -f, --file string    File to hash
```

**Examples:**

```bash
gocryptic hash --input 'hello world'
# SHA256  b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576...  (stdin)

gocryptic hash --algo all --file myfile.bin
# MD5       d41d8cd98f00b204e9800998ecf8427e
# SHA1      da39a3ee5e6b4b0d3255bfef95601890afd80709
# SHA256    e3b0c44298fc1c149afbf4c8996fb924...
# ...
```

---

### `keygen`

```
gocryptic keygen [flags]

Flags:
  -t, --type string    aes | chacha20 | rsa | ecdsa | password  (default "aes")
      --bits int       Key size in bits (AES: 128/192/256; RSA: ≥2048)  (default 256)
      --priv string    Private key output path  (default "priv.pem")
      --pub string     Public key output path  (default "pub.pem")
  -l, --length int     Password length  (default 24)
      --special        Include special characters in password
```

---

### `encode`

```
gocryptic encode [flags]

Flags:
  -F, --format string   base64 | base64url | base64raw | hex  (default "base64")
  -d, --decode          Decode instead of encode
  -i, --input string    String to encode/decode
  -f, --file string     File to encode/decode
  -o, --output string   Output file
```

---

### `sign`

```
gocryptic sign [flags]

Flags:
  -i, --input string    String to sign
  -f, --file string     File to sign
  -k, --key string      Private key PEM (required)
  -o, --output string   Signature output file (default: <input>.sig)
```

Outputs a binary `.sig` file, or hex to stdout when no output file is specified.

---

### `verify`

```
gocryptic verify [flags]

Flags:
  -i, --input string     String to verify
  -f, --file string      File to verify
  -s, --sig string       Binary signature file
      --sig-hex string   Signature as hex string
  -k, --key string       Public key PEM (required)
```

---

## Packet Format

Every GoCryptic-encrypted file starts with a 5-byte header:

```
GCRY (4 bytes) | Algorithm byte (1 byte) | ...
```

| Algo byte | Algorithm                       |
| --------- | ------------------------------- |
| `0x01`    | AES-256-GCM                     |
| `0x02`    | AES-256-CBC + HMAC-SHA256       |
| `0x03`    | XChaCha20-Poly1305              |
| `0x04`    | RSA hybrid (OAEP + AES-256-GCM) |

This lets `decrypt --algo auto` detect the algorithm without any ambiguity.

---

## Security Notes

- **KDF:** All password-based algorithms use **scrypt** (N=2¹⁵, r=8, p=1), producing a 32-byte key from a fresh random 32-byte salt.
- **AES-CBC:** Uses encrypt-then-MAC with a separate HMAC-SHA256 key to prevent padding-oracle attacks.
- **RSA:** Hybrid mode — plaintext is never directly RSA-encrypted; a random AES-256-GCM session key is wrapped with RSA-OAEP (SHA-256).
- **Minimum RSA key size:** 2048 bits (enforced). Recommended: 4096 bits.
- **ECDSA:** P-256 curve with SHA-256 digest; signatures encoded as ASN.1 DER.
- **Password safety:** Prefer `--prompt`, `--key-env`, or `--key-file` over `--key` in production — plain `--key` values appear in shell history and `ps` output.

---

## Development

```bash
make test                # run the full test suite with -race
make lint                # run golangci-lint
make run-demo            # quick smoke-test of all features
bash test_realworld.sh   # end-to-end integration tests
```

---

## License

MIT — see [LICENSE](LICENSE)
