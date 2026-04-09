# AGENTS.md

## Purpose

- Keep `go-keychain-text-crypto` a minimal macOS sample.
- Demonstrate Go + Keychain + `LAContext`.

## Priorities

- Small code
- Clear flow
- Correct crypto
- Safe plaintext handling

## Rules

- Keep commands limited to `init`, `edit`, `dump`, `lock`, `export-key`, `import-key` unless asked otherwise.
- Keep plaintext unstructured.
- Keep encrypted and recovery envelopes in YAML.
- Keep auth in `keychain_darwin.go`.
- Use `LAContext` before Keychain reads.
- Keep writes atomic.
- Keep temp plaintext files `0600` and short-lived.
- Update `DESIGN.md` when behavior changes.

## Verification

- Run `gofmt -w *.go`
- Run `go build ./...`
- Run `go test ./...`

## Avoid

- Session caches
- Extra subcommands
- Schema validation for plaintext
- Deprecated Keychain auth APIs
