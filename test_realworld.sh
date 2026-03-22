#!/usr/bin/env bash
# GoCryptic — Real-World Integration Tests
# Based on manual testing session, March 2026.
# Run from the project root after: go mod tidy && make build
# Usage: bash test_realworld.sh

set -uo pipefail

BIN="./gocryptic"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0

pass() { echo -e "${GREEN}  ✓ PASS${NC}  $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo -e "${RED}  ✗ FAIL${NC}  $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
section() { echo -e "\n${YELLOW}══ $1 ══${NC}"; }

# ─────────────────────────────────────────────────────────────
section "1 · Binary sanity check"
# ─────────────────────────────────────────────────────────────

$BIN --help 2>&1 | grep -q "Available Commands:" && pass "binary runs and shows help" || fail "binary help"

# ─────────────────────────────────────────────────────────────
section "2 · AES-GCM string encrypt / decrypt"
# ─────────────────────────────────────────────────────────────

CT=$($BIN encrypt --algo aes-gcm --input 'Hello, GoCryptic!' --key 'mypassword' 2>/dev/null)
[[ "$CT" == R0NSW* ]] && pass "ciphertext starts with GCRY magic (R0NSW...)" || fail "magic header missing"

PT=$($BIN decrypt --input "$CT" --key 'mypassword' 2>/dev/null)
[[ "$PT" == "Hello, GoCryptic!" ]] && pass "AES-GCM string round-trip" || fail "AES-GCM string round-trip"

# ─────────────────────────────────────────────────────────────
section "3 · Wrong password is rejected"
# ─────────────────────────────────────────────────────────────

if $BIN decrypt --input "$CT" --key 'wrongpassword' 2>/dev/null 1>/dev/null; then
  fail "wrong password was accepted"
else
  pass "wrong password correctly rejected"
fi

# ─────────────────────────────────────────────────────────────
section "4 · File encrypt / decrypt"
# ─────────────────────────────────────────────────────────────

echo 'This is my secret document.' > "$TMPDIR/secret.txt"
$BIN encrypt --algo aes-gcm --file "$TMPDIR/secret.txt" --key 'mypassword' 2>/dev/null
[[ -f "$TMPDIR/secret.txt.gcry" ]] && pass "encrypted file created (secret.txt.gcry)" || fail "encrypted file missing"

$BIN decrypt --file "$TMPDIR/secret.txt.gcry" --key 'mypassword' 2>/dev/null
CONTENT=$(cat "$TMPDIR/secret.txt")
[[ "$CONTENT" == "This is my secret document." ]] && pass "file decrypt restores original content" || fail "file content mismatch"

# ─────────────────────────────────────────────────────────────
section "5 · Hashing"
# ─────────────────────────────────────────────────────────────

# Known SHA-256 digest for 'Hello, GoCryptic!'
DIGEST=$($BIN hash --input 'Hello, GoCryptic!' 2>/dev/null | awk '{print $2}')
[[ "$DIGEST" == "a41249595af2645ed7cf85d8a48699d085998687b66e296639ceafc8c488edc4" ]] \
  && pass "SHA-256 digest matches known value" || fail "SHA-256 mismatch (got: $DIGEST)"

# Cross-check against system sha256
SYSTEM_DIGEST=$(echo -n 'Hello, GoCryptic!' | shasum -a 256 | awk '{print $1}')
[[ "$DIGEST" == "$SYSTEM_DIGEST" ]] && pass "digest matches system shasum" || fail "digest differs from system shasum"

# --algo all produces all 7 algorithms
ALL_OUT=$($BIN hash --algo all --input 'Hello, GoCryptic!' 2>/dev/null)
for algo in MD5 SHA1 SHA256 SHA384 SHA512 SHA3-256 SHA3-512; do
  echo "$ALL_OUT" | grep -q "^$algo" \
    && pass "--algo all: $algo present" || fail "--algo all: $algo missing"
done

# ─────────────────────────────────────────────────────────────
section "6 · Base64 encoding / decoding"
# ─────────────────────────────────────────────────────────────

ENC=$($BIN encode --format base64 --input 'Hello, GoCryptic!' 2>/dev/null)
[[ "$ENC" == "SGVsbG8sIEdvQ3J5cHRpYyE=" ]] && pass "base64 encode" || fail "base64 encode (got: $ENC)"

DEC=$($BIN encode --decode --format base64 --input 'SGVsbG8sIEdvQ3J5cHRpYyE=' 2>/dev/null)
[[ "$DEC" == "Hello, GoCryptic!" ]] && pass "base64 decode" || fail "base64 decode"

# ─────────────────────────────────────────────────────────────
section "7 · Hex encoding / decoding"
# ─────────────────────────────────────────────────────────────

HEX=$($BIN encode --format hex --input 'Hello, GoCryptic!' 2>/dev/null)
[[ "$HEX" == "48656c6c6f2c20476f4372797074696321" ]] && pass "hex encode" || fail "hex encode (got: $HEX)"

UNHEX=$($BIN encode --decode --format hex --input '48656c6c6f2c20476f4372797074696321' 2>/dev/null)
[[ "$UNHEX" == "Hello, GoCryptic!" ]] && pass "hex decode" || fail "hex decode"

# ─────────────────────────────────────────────────────────────
section "8 · RSA key pair generation"
# ─────────────────────────────────────────────────────────────

PRIV="$TMPDIR/priv.pem"
PUB="$TMPDIR/pub.pem"
$BIN keygen --type rsa --bits 2048 --priv "$PRIV" --pub "$PUB" 2>/dev/null
[[ -f "$PRIV" && -f "$PUB" ]] && pass "RSA key pair files created" || fail "RSA key pair missing"

PRIV_PERMS=$(stat -f "%Mp%Lp" "$PRIV" 2>/dev/null || stat -c "%a" "$PRIV" 2>/dev/null)
[[ "$PRIV_PERMS" == "0600" || "$PRIV_PERMS" == "600" ]] \
  && pass "private key has mode 0600" || fail "private key permissions wrong (got: $PRIV_PERMS)"

# ─────────────────────────────────────────────────────────────
section "9 · Digital signatures (RSA-PSS)"
# ─────────────────────────────────────────────────────────────

echo 'This is my secret document.' > "$TMPDIR/sigdata.txt"
$BIN sign --file "$TMPDIR/sigdata.txt" --key "$PRIV" 2>/dev/null
[[ -f "$TMPDIR/sigdata.txt.sig" ]] && pass "signature file created" || fail "signature file missing"

SIG_SIZE=$(wc -c < "$TMPDIR/sigdata.txt.sig")
[[ "$SIG_SIZE" -eq 256 ]] && pass "RSA-2048 signature is 256 bytes" || fail "unexpected signature size: $SIG_SIZE"

$BIN verify --file "$TMPDIR/sigdata.txt" --sig "$TMPDIR/sigdata.txt.sig" --key "$PUB" 2>/dev/null \
  && pass "valid signature verifies" || fail "valid signature rejected"

echo 'TAMPERED content' > "$TMPDIR/tampered.txt"
if $BIN verify --file "$TMPDIR/tampered.txt" --sig "$TMPDIR/sigdata.txt.sig" --key "$PUB" 2>/dev/null; then
  fail "tampered file incorrectly verified"
else
  pass "tampered file correctly rejected"
fi

# ─────────────────────────────────────────────────────────────
section "10 · Password generation"
# ─────────────────────────────────────────────────────────────

PW=$($BIN keygen --type password --length 32 --special 2>/dev/null | tail -1)
[[ ${#PW} -eq 32 ]] && pass "generated password is 32 chars" || fail "password length wrong (got: ${#PW})"

PW2=$($BIN keygen --type password --length 32 --special 2>/dev/null | tail -1)
[[ "$PW" != "$PW2" ]] && pass "consecutive passwords are unique" || fail "consecutive passwords are identical"

# ─────────────────────────────────────────────────────────────
section "11 · ChaCha20 string round-trip"
# ─────────────────────────────────────────────────────────────

CT=$($BIN encrypt --algo chacha20 --input 'ChaCha20 test' --key 'mypassword' 2>/dev/null)
PT=$($BIN decrypt --input "$CT" --key 'mypassword' 2>/dev/null)
[[ "$PT" == "ChaCha20 test" ]] && pass "ChaCha20 string round-trip" || fail "ChaCha20 string round-trip"

# ─────────────────────────────────────────────────────────────
section "12 · AES-CBC string round-trip"
# ─────────────────────────────────────────────────────────────

CT=$($BIN encrypt --algo aes-cbc --input 'AES-CBC test' --key 'mypassword' 2>/dev/null)
PT=$($BIN decrypt --input "$CT" --key 'mypassword' 2>/dev/null)
[[ "$PT" == "AES-CBC test" ]] && pass "AES-CBC string round-trip" || fail "AES-CBC string round-trip"

# ─────────────────────────────────────────────────────────────
section "13 · Auto-detect algorithm on decrypt"
# ─────────────────────────────────────────────────────────────

for algo in aes-gcm aes-cbc chacha20; do
  CT=$($BIN encrypt --algo "$algo" --input "autodetect-$algo" --key 'mypassword' 2>/dev/null)
  PT=$($BIN decrypt --algo auto --input "$CT" --key 'mypassword' 2>/dev/null)
  [[ "$PT" == "autodetect-$algo" ]] && pass "auto-detect: $algo" || fail "auto-detect: $algo"
done

# ─────────────────────────────────────────────────────────────
section "14 · Directory encrypt / decrypt"
# ─────────────────────────────────────────────────────────────

VAULT="$TMPDIR/vault"
mkdir -p "$VAULT"
echo 'Bank account: 12345' > "$VAULT/finance.txt"
echo 'Password: hunter2'  > "$VAULT/passwords.txt"
echo 'Dear diary...'      > "$VAULT/diary.txt"

$BIN encrypt --algo aes-gcm --dir "$VAULT" --key 'mypassword' 2>/dev/null
[[ -f "$VAULT/finance.txt.gcry" && ! -f "$VAULT/finance.txt" ]] \
  && pass "directory encrypt: .gcry files created, originals removed" || fail "directory encrypt"

$BIN decrypt --dir "$VAULT" --key 'mypassword' 2>/dev/null
[[ $(cat "$VAULT/finance.txt")   == "Bank account: 12345" ]] && pass "vault/finance.txt restored"   || fail "vault/finance.txt"
[[ $(cat "$VAULT/passwords.txt") == "Password: hunter2"   ]] && pass "vault/passwords.txt restored" || fail "vault/passwords.txt"
[[ $(cat "$VAULT/diary.txt")     == "Dear diary..."        ]] && pass "vault/diary.txt restored"     || fail "vault/diary.txt"

# ─────────────────────────────────────────────────────────────
section "15 · --key-env (password from environment variable)"
# ─────────────────────────────────────────────────────────────

export GCRY_PASS='env-sourced-password'

CT=$(GCRY_PASS='env-sourced-password' $BIN encrypt --algo aes-gcm --input 'env var test' --key-env GCRY_PASS 2>/dev/null)
[[ "$CT" == R0NSW* ]] && pass "--key-env: ciphertext produced" || fail "--key-env: no ciphertext"

PT=$($BIN decrypt --input "$CT" --key-env GCRY_PASS 2>/dev/null)
[[ "$PT" == "env var test" ]] && pass "--key-env: decrypt round-trip" || fail "--key-env: decrypt mismatch (got: '$PT')"

# Unset variable should error
if $BIN encrypt --algo aes-gcm --input 'x' --key-env GCRY_DEFINITELY_NOT_SET 2>/dev/null; then
  fail "--key-env: unset variable was accepted"
else
  pass "--key-env: unset variable correctly rejected"
fi

unset GCRY_PASS

# ─────────────────────────────────────────────────────────────
section "16 · --key-file (password from file)"
# ─────────────────────────────────────────────────────────────

KEYFILE="$TMPDIR/mypassword.key"
echo 'file-sourced-password' > "$KEYFILE"
chmod 600 "$KEYFILE"

CT=$($BIN encrypt --algo aes-gcm --input 'key file test' --key-file "$KEYFILE" 2>/dev/null)
[[ "$CT" == R0NSW* ]] && pass "--key-file: ciphertext produced" || fail "--key-file: no ciphertext"

PT=$($BIN decrypt --input "$CT" --key-file "$KEYFILE" 2>/dev/null)
[[ "$PT" == "key file test" ]] && pass "--key-file: decrypt round-trip" || fail "--key-file: decrypt mismatch (got: '$PT')"

# Empty key file should error
EMPTY_KEY="$TMPDIR/empty.key"
echo '' > "$EMPTY_KEY"
if $BIN encrypt --algo aes-gcm --input 'x' --key-file "$EMPTY_KEY" 2>/dev/null; then
  fail "--key-file: empty file was accepted"
else
  pass "--key-file: empty file correctly rejected"
fi

# Missing key file should error
if $BIN encrypt --algo aes-gcm --input 'x' --key-file '/nonexistent/key.txt' 2>/dev/null; then
  fail "--key-file: missing file was accepted"
else
  pass "--key-file: missing file correctly rejected"
fi

# ─────────────────────────────────────────────────────────────
section "17 · --prompt and --confirm (non-TTY rejection)"
# ─────────────────────────────────────────────────────────────

# In a non-interactive script stdin is a pipe, so --prompt must fail gracefully.
# We verify the error path rather than the happy path (which requires a real TTY).
if $BIN encrypt --algo aes-gcm --input 'x' --prompt </dev/null 2>/dev/null; then
  fail "--prompt: accepted in non-TTY context (should have failed)"
else
  pass "--prompt: correctly rejected when stdin is not a TTY"
fi

if $BIN encrypt --algo aes-gcm --input 'x' --prompt --confirm </dev/null 2>/dev/null; then
  fail "--prompt --confirm: accepted in non-TTY context (should have failed)"
else
  pass "--prompt --confirm: correctly rejected when stdin is not a TTY"
fi

if $BIN decrypt --input 'someciphertext' --prompt </dev/null 2>/dev/null; then
  fail "--prompt on decrypt: accepted in non-TTY context"
else
  pass "--prompt on decrypt: correctly rejected when stdin is not a TTY"
fi

# ─────────────────────────────────────────────────────────────
echo -e "\n══════════════════════════════════════════"
echo -e " Results: ${GREEN}${PASS_COUNT} passed${NC}  ${RED}${FAIL_COUNT} failed${NC}"
echo -e "══════════════════════════════════════════"
[[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1