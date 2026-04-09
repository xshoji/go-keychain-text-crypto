# go-keychain-text-crypto

A minimal Go sample for encrypting text with macOS Keychain and `LAContext` authentication.

## Overview

This tool demonstrates:
- Encrypting free text with Go
- Storing encryption keys in macOS Keychain
- Requiring `LAContext` authentication before decryption

## Features

- **Secure Encryption**: Uses XChaCha20-Poly1305 for file encryption
- **Keychain Integration**: Stores encryption keys securely in macOS Keychain
- **Biometric Authentication**: Requires Touch ID/Face ID or password via LAContext
- **Recovery Mechanism**: Export/import encrypted keys with passphrase protection
- **Atomic Operations**: All file writes are atomic for data safety

## Installation

```bash
go install github.com/xshoji/go-keychain-text-crypto@latest
```

Or clone and build locally:
```bash
git clone https://github.com/xshoji/go-keychain-text-crypto.git
cd go-keychain-text-crypto
go build .
```

## Usage

### Initialize a new encrypted file
```bash
go-keychain-text-crypto init
```

### Edit encrypted content
```bash
go-keychain-text-crypto edit
```
This opens your `$EDITOR` with the decrypted content. Changes are re-encrypted on save.

### Display decrypted content
```bash
go-keychain-text-crypto dump
```

### Export recovery key
```bash
go-keychain-text-crypto export-key
```
Creates a passphrase-protected recovery file.

### Import recovery key
```bash
go-keychain-text-crypto import-key --in ./secrets.recovery.yaml
```

## Commands

- `init`: Create an empty encrypted file and store a random DEK in Keychain
- `edit`: Decrypt to a temp file, open `$EDITOR`, then re-encrypt on save
- `dump`: Authenticate and print decrypted plaintext to stdout
- `lock`: No-op (kept for CLI symmetry)
- `export-key`: Export the DEK wrapped by a recovery passphrase
- `import-key`: Import a wrapped DEK back into Keychain

## Security Design

- **Encryption**: XChaCha20-Poly1305 for file encryption
- **Key Derivation**: Argon2id for recovery passphrase hashing
- **Authentication**: LAContext with biometric/password fallback
- **Key Storage**: Keys stored in macOS Keychain
- **Memory Safety**: No plaintext cached in memory
- **File Safety**: Atomic file operations with 0600 permissions

See [DESIGN.md](DESIGN.md) for detailed security architecture.

## Delete keychain

```
security delete-generic-password -l "go-keychain-text-crypto"
```