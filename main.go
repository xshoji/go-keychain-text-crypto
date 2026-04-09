package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const defaultVaultFile = "./secrets.ssec"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return nil
	}

	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "edit":
		return runEdit(args[1:])
	case "dump":
		return runDump(args[1:])
	case "lock":
		return runLock(args[1:])
	case "export-key":
		return runExportKey(args[1:])
	case "import-key":
		return runImportKey(args[1:])
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "go-keychain-text-crypto")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  go-keychain-text-crypto init [--file PATH]")
	fmt.Fprintln(w, "  go-keychain-text-crypto edit [--file PATH]")
	fmt.Fprintln(w, "  go-keychain-text-crypto dump [--file PATH]")
	fmt.Fprintln(w, "  go-keychain-text-crypto lock [--file PATH]")
	fmt.Fprintln(w, "  go-keychain-text-crypto export-key [--file PATH] [--out PATH]")
	fmt.Fprintln(w, "  go-keychain-text-crypto import-key --in PATH [--file PATH]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Tip:")
	fmt.Fprintln(w, "  go-keychain-text-crypto dump | rg github")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func runInit(args []string) error {
	fs := newFlagSet("init")
	filePath := fs.String("file", defaultVaultFile, "path to the encrypted vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init does not accept positional arguments")
	}

	path, err := resolveVaultPath(*filePath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault file already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	key, err := randomBytes(32)
	if err != nil {
		return err
	}
	keyID, err := randomID()
	if err != nil {
		return err
	}
	if err := keychainStore(keyID, key); err != nil {
		return fmt.Errorf("store key in Keychain: %w", err)
	}

	now := time.Now().UTC()
	envelope := &vaultEnvelope{
		Version:   1,
		Type:      "secrets-file",
		KeyID:     keyID,
		CreatedAt: now.Format(time.RFC3339),
		UpdatedAt: now.Format(time.RFC3339),
	}

	encoded, err := encryptVaultPlaintext(nil, envelope, key, now)
	if err != nil {
		_ = keychainDelete(keyID)
		return err
	}
	if err := writeFileAtomic(path, encoded, 0o600); err != nil {
		_ = keychainDelete(keyID)
		return err
	}

	fmt.Fprintf(os.Stdout, "initialized %s\n", path)
	return nil
}

func runEdit(args []string) error {
	fs := newFlagSet("edit")
	filePath := fs.String("file", defaultVaultFile, "path to the encrypted vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("edit does not accept positional arguments")
	}

	path, err := resolveVaultPath(*filePath)
	if err != nil {
		return err
	}
	key, err := loadVaultKey(path, "Authenticate to edit the encrypted text")
	if err != nil {
		return err
	}
	plaintext, envelope, err := loadVaultPlaintext(path, key)
	if err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "go-keychain-text-crypto-edit-")
	if err != nil {
		return err
	}
	defer removeTempDir(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return err
	}

	tempPath := filepath.Join(tempDir, "vault.txt")
	if err := os.WriteFile(tempPath, plaintext, 0o600); err != nil {
		return err
	}
	if err := launchEditor(tempPath); err != nil {
		return err
	}

	edited, err := os.ReadFile(tempPath)
	if err != nil {
		return err
	}
	if bytes.Equal(edited, plaintext) {
		fmt.Fprintln(os.Stdout, "no changes")
		return nil
	}

	encoded, err := encryptVaultPlaintext(edited, envelope, key, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, encoded, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "saved %s\n", path)
	return nil
}

func runDump(args []string) error {
	fs := newFlagSet("dump")
	filePath := fs.String("file", defaultVaultFile, "path to the encrypted vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("dump does not accept positional arguments")
	}

	path, err := resolveVaultPath(*filePath)
	if err != nil {
		return err
	}
	key, err := loadVaultKey(path, "Authenticate to decrypt the text")
	if err != nil {
		return err
	}
	plaintext, _, err := loadVaultPlaintext(path, key)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext)
	return err
}

func runLock(args []string) error {
	fs := newFlagSet("lock")
	_ = fs.String("file", defaultVaultFile, "path to the encrypted vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("lock does not accept positional arguments")
	}

	// This sample does not keep an unlocked session in memory.
	fmt.Fprintln(os.Stdout, "locked")
	return nil
}

func runExportKey(args []string) error {
	fs := newFlagSet("export-key")
	filePath := fs.String("file", defaultVaultFile, "path to the encrypted vault file")
	outPath := fs.String("out", "./secrets.recovery.yaml", "path to the recovery key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("export-key does not accept positional arguments")
	}

	vaultPath, err := resolveVaultPath(*filePath)
	if err != nil {
		return err
	}
	recoveryPath, err := filepath.Abs(*outPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(recoveryPath); err == nil {
		return fmt.Errorf("recovery file already exists: %s", recoveryPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	envelope, err := readVaultEnvelope(vaultPath)
	if err != nil {
		return err
	}
	key, err := keychainLoad(envelope.KeyID, "Authenticate to export the recovery key")
	if err != nil {
		return fmt.Errorf("read key from Keychain: %w", err)
	}

	passphrase, err := promptPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)
	confirm, err := promptPassphrase("Confirm recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(confirm)
	if !bytes.Equal(passphrase, confirm) {
		return fmt.Errorf("recovery passphrases did not match")
	}

	recovery, err := newRecoveryFile(envelope.KeyID, key, passphrase, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := yaml.Marshal(recovery)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(recoveryPath, encoded, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "exported recovery key to %s\n", recoveryPath)
	return nil
}

func runImportKey(args []string) error {
	fs := newFlagSet("import-key")
	inPath := fs.String("in", "", "path to the recovery key file")
	filePath := fs.String("file", "", "optional path to the encrypted vault file for verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("import-key does not accept positional arguments")
	}
	if strings.TrimSpace(*inPath) == "" {
		return fmt.Errorf("--in is required")
	}

	recoveryPath, err := filepath.Abs(*inPath)
	if err != nil {
		return err
	}
	recoveryBytes, err := os.ReadFile(recoveryPath)
	if err != nil {
		return err
	}

	var recovery recoveryFile
	if err := yaml.Unmarshal(recoveryBytes, &recovery); err != nil {
		return fmt.Errorf("parse recovery file: %w", err)
	}
	passphrase, err := promptPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)

	key, err := unwrapRecoveryKey(&recovery, passphrase)
	if err != nil {
		return err
	}

	if strings.TrimSpace(*filePath) != "" {
		path, err := resolveVaultPath(*filePath)
		if err != nil {
			return err
		}
		envelope, err := readVaultEnvelope(path)
		if err != nil {
			return err
		}
		if envelope.KeyID != recovery.KeyID {
			return fmt.Errorf("recovery key_id %q does not match vault key_id %q", recovery.KeyID, envelope.KeyID)
		}
		if _, _, err := loadVaultPlaintext(path, key); err != nil {
			return fmt.Errorf("verify imported key against vault: %w", err)
		}
	}

	if err := keychainStore(recovery.KeyID, key); err != nil {
		return fmt.Errorf("store imported key in Keychain: %w", err)
	}

	fmt.Fprintf(os.Stdout, "imported key %s into Keychain\n", recovery.KeyID)
	return nil
}

func resolveVaultPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("vault path must not be empty")
	}
	return filepath.Abs(path)
}

func loadVaultKey(vaultPath string, prompt string) ([]byte, error) {
	envelope, err := readVaultEnvelope(vaultPath)
	if err != nil {
		return nil, err
	}
	return keychainLoad(envelope.KeyID, prompt)
}

func launchEditor(path string) error {
	editor := strings.TrimSpace(os.Getenv("EDITOR"))
	if editor == "" {
		editor = "vi"
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s %q", editor, path))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func promptPassphrase(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("a terminal is required for passphrase input")
	}
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	return value, nil
}

func removeTempDir(path string) {
	_ = os.RemoveAll(path)
}
