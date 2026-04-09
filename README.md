# go-keychain-text-crypto

`go-keychain-text-crypto` is a minimal macOS sample that encrypts free text with Go, stores the data-encryption key in Keychain, and requires `LAContext` authentication before decrypting it.

<img width="802" height="465" alt="image" src="https://github.com/user-attachments/assets/37f8aa98-a359-4def-a5d5-44de1854b55e" />


It is intentionally small. The goal is to show a clear end-to-end flow for:

- file encryption with `XChaCha20-Poly1305`
- Keychain-backed key storage
- biometric or device-password authentication via `LAContext`
- passphrase-protected recovery key export/import

## What This Sample Is

- A single-file encrypted text workflow
- Plaintext as raw text with no schema
- A macOS-only sample focused on Keychain + `LAContext`

## What This Sample Is Not

- A full password manager
- A cross-platform CLI
- A session-caching design
- A structured secret store with field-level parsing

## Requirements

- macOS
- Go installed locally if you build from source
- Access to LocalAuthentication on the machine
- A terminal for passphrase entry during `export-key` and `import-key`

## Install

```bash
go install github.com/xshoji/go-keychain-text-crypto@latest
```

Or build locally:

```bash
git clone https://github.com/xshoji/go-keychain-text-crypto.git
cd go-keychain-text-crypto
go build .
```

## Quick Start

Initialize a new encrypted vault:

```bash
go-keychain-text-crypto init
```

This creates `./secrets.ssec` and stores a random 32-byte DEK in macOS Keychain.

Edit the plaintext:

```bash
go-keychain-text-crypto edit
```

The command:

- authenticates with `LAContext`
- decrypts to a short-lived temp file
- opens `$EDITOR` or falls back to `vi`
- re-encrypts and atomically rewrites the vault if content changed

Print the plaintext to stdout:

```bash
go-keychain-text-crypto dump
```

Create a recovery file:

```bash
go-keychain-text-crypto export-key
```

Restore a key from a recovery file:

```bash
go-keychain-text-crypto import-key --in ./secrets.recovery.yaml --file ./secrets.ssec
```

The `--file` flag on `import-key` is optional, but recommended because it verifies that the imported key can actually decrypt the target vault.

## Commands

### `init`

```bash
go-keychain-text-crypto init [--file PATH]
```

- default vault path: `./secrets.ssec`
- fails if the vault file already exists
- creates an empty encrypted vault and stores the matching DEK in Keychain

### `edit`

```bash
go-keychain-text-crypto edit [--file PATH]
```

- authenticates before reading the DEK from Keychain
- writes plaintext to a `0600` temp file in a private temp directory
- opens the file in `$EDITOR` or `vi`
- prints `no changes` if the file was not modified

### `dump`

```bash
go-keychain-text-crypto dump [--file PATH]
```

- authenticates before decryption
- writes the exact stored plaintext bytes to stdout

### `lock`

```bash
go-keychain-text-crypto lock [--file PATH]
```

- prints `locked`
- does not revoke any session because this sample keeps no unlocked session cache in memory

### `export-key`

```bash
go-keychain-text-crypto export-key [--file PATH] [--out PATH]
```

- default vault path: `./secrets.ssec`
- default recovery path: `./secrets.recovery.yaml`
- authenticates before reading the DEK from Keychain
- prompts twice for a non-empty recovery passphrase
- writes a `0600` YAML recovery envelope
- fails if the output file already exists

### `import-key`

```bash
go-keychain-text-crypto import-key --in PATH [--file PATH]
```

- requires `--in`
- prompts for the recovery passphrase once
- unwraps the DEK and stores it back in Keychain
- if `--file` is given, verifies that `key_id` matches and that decryption succeeds

## Files

- Vault file: `./secrets.ssec` by default
- Recovery file: `./secrets.recovery.yaml` by default
- Both vault and recovery data are YAML envelopes
- Plaintext remains unstructured and is encrypted as one blob

See [DESIGN.md](DESIGN.md) for the full file formats and security notes.

## Security Model

- File encryption uses `XChaCha20-Poly1305`
- Recovery wrapping uses `XChaCha20-Poly1305`
- Recovery passphrases are stretched with `Argon2id`
- Keys are stored in macOS Keychain
- `LAContext` runs before Keychain reads
- Authentication can fall back to the device password when biometry is unavailable or locked out
- Encrypted file writes are atomic
- Temp plaintext files are short-lived and created with restrictive permissions

## Operational Notes

- `dump` prints plaintext to stdout, so avoid piping it into logs or shell history capture workflows
- `edit` relies on the editor process to avoid making extra plaintext copies
- `export-key` is your recovery path if the local Keychain item is removed or unavailable
- The vault file contains a `key_id`, so moving the encrypted file does not break decryption by itself

## Remove a Stored Keychain Item

Keys are stored as generic passwords under service `go-keychain-text-crypto` and account `<key_id>`.

First inspect the vault's `key_id`:

```bash
sed -n 's/^key_id: //p' ./secrets.ssec
```

Then delete the matching Keychain item:

```bash
security delete-generic-password -s "go-keychain-text-crypto" -a "<key_id>"
```

## Development

```bash
gofmt -w *.go
go build ./...
go test ./...
```
