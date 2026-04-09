# go-keychain-text-crypto Design

## Overview

`go-keychain-text-crypto` is a minimal sample for:

- encrypting free text with Go
- storing the encryption key in macOS Keychain
- requiring `LAContext` authentication before decryption

The sample keeps the CLI intentionally small.

## Commands

- `init`: create an empty encrypted file and store a random DEK in Keychain
- `edit`: decrypt to a temp file, open `$EDITOR`, then re-encrypt on save
- `dump`: authenticate and print decrypted plaintext to stdout
- `lock`: no-op in this sample; kept for CLI symmetry
- `export-key`: export the DEK wrapped by a recovery passphrase
- `import-key`: import a wrapped DEK back into Keychain

## Plaintext Format

- Plaintext is arbitrary free text
- No schema is enforced
- The sample does not parse or normalize plaintext
- `dump` returns the exact stored bytes

## Encrypted File Format

The encrypted file uses a small YAML envelope:

```yaml
version: 1
type: secrets-file
key_id: "01JRG7D1QJEXAMPLE"
created_at: "2026-04-09T11:00:00Z"
updated_at: "2026-04-09T12:00:00Z"

cipher:
  algorithm: xchacha20poly1305
  nonce: "base64:..."

payload:
  encoding: base64
  ciphertext: "base64:..."
```

Properties:

- Entire plaintext is encrypted as one blob
- No plaintext metadata is exposed
- `key_id` identifies the matching Keychain item

## Recovery File Format

The recovery file is also YAML:

```yaml
version: 1
type: recovery-key
key_id: "01JRG7D1QJEXAMPLE"
created_at: "2026-04-09T12:30:00Z"

kdf:
  algorithm: argon2id
  time: 3
  memory_kib: 65536
  threads: 4
  salt: "base64:..."

wrap:
  algorithm: xchacha20poly1305
  nonce: "base64:..."
  ciphertext: "base64:..."
```

Properties:

- The raw DEK is never exported in plaintext
- Recovery needs the recovery file and recovery passphrase

## Crypto Choices

- DEK: 32 random bytes
- File cipher: `XChaCha20-Poly1305`
- Recovery KDF: `Argon2id`
- Recovery wrap cipher: `XChaCha20-Poly1305`

## Authentication Model

- DEKs are stored in macOS Keychain
- `LAContext` runs before Keychain reads
- Authentication allows password fallback when biometry is unavailable or locked out
- This sample keeps no unlocked session cache in memory

## Safety Rules

- Allow plaintext only in the `edit` temp file and `dump` stdout
- Create temp files with `0600`
- Rewrite encrypted files atomically
- Never log plaintext or recovery secrets

## Non-Goals

- session caching
- search indexes
- structured secret schemas
- cross-platform support
- full password-manager UX
