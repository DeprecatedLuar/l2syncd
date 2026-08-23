//go:build linux

// Package connection owns l2sync SSH key material and restricted grants.
package connection

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"l2syncd/internal/peername"
)

const (
	sshDirectoryMode = 0o700
	privateKeyMode   = 0o600
	publicKeyMode    = 0o644
	authorizedMode   = 0o600
	keyFilename      = "id_l2sync"
	keyType          = "ssh-ed25519"
	commentPrefix    = "l2sync:"
	forcedBinary     = "l2sync"
	fingerprintBytes = 12
)

// Paths identifies the installation key and grant files. It is explicit so
// bootstrap behavior can be tested without touching a real SSH directory.
type Paths struct {
	PrivateKey     string
	PublicKey      string
	AuthorizedKeys string
}

// DefaultPaths returns paths under the current user's ~/.ssh directory.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("find home directory: %w", err)
	}
	sshDir := filepath.Join(home, ".ssh")
	return Paths{
		PrivateKey:     filepath.Join(sshDir, keyFilename),
		PublicKey:      filepath.Join(sshDir, keyFilename+".pub"),
		AuthorizedKeys: filepath.Join(sshDir, "authorized_keys"),
	}, nil
}

// EnsureKey returns the installation public key, generating the Ed25519 key
// pair when neither key file exists. Partial or inconsistent key material is
// an error and is never silently repaired.
func EnsureKey(paths Paths) (string, error) {
	privateExists, err := exists(paths.PrivateKey)
	if err != nil {
		return "", err
	}
	publicExists, err := exists(paths.PublicKey)
	if err != nil {
		return "", err
	}
	if privateExists != publicExists {
		return "", errors.New("incomplete l2sync key pair")
	}
	if privateExists {
		if err := validateCredentialDirectory(filepath.Dir(paths.PrivateKey)); err != nil {
			return "", err
		}
		if err := validateCredentialFile(paths.PrivateKey, true); err != nil {
			return "", err
		}
		if err := validateCredentialFile(paths.PublicKey, false); err != nil {
			return "", err
		}
		privateContents, err := os.ReadFile(paths.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("read l2sync private key: %w", err)
		}
		block, trailing := pem.Decode(privateContents)
		if block == nil || len(bytes.TrimSpace(trailing)) != 0 || block.Type != "PRIVATE KEY" {
			return "", errors.New("l2sync private key is not one PKCS#8 key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse l2sync private key: %w", err)
		}
		private, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("l2sync private key is not Ed25519")
		}
		line, err := os.ReadFile(paths.PublicKey)
		if err != nil {
			return "", fmt.Errorf("read l2sync public key: %w", err)
		}
		normalized, err := NormalizePublicKey(string(line))
		if err != nil {
			return "", err
		}
		if normalized != marshalPublicKey(private.Public().(ed25519.PublicKey)) {
			return "", errors.New("l2sync public key does not match its private key")
		}
		return normalized, nil
	}
	if err := os.MkdirAll(filepath.Dir(paths.PrivateKey), sshDirectoryMode); err != nil {
		return "", fmt.Errorf("create SSH directory: %w", err)
	}
	if err := validateCredentialDirectory(filepath.Dir(paths.PrivateKey)); err != nil {
		return "", err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate Ed25519 key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", fmt.Errorf("encode Ed25519 private key: %w", err)
	}
	publicLine := marshalPublicKey(public)
	if err := writeExclusive(paths.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), privateKeyMode); err != nil {
		return "", fmt.Errorf("write l2sync private key: %w", err)
	}
	if err := writeExclusive(paths.PublicKey, []byte(publicLine+"\n"), publicKeyMode); err != nil {
		_ = os.Remove(paths.PrivateKey)
		return "", fmt.Errorf("write l2sync public key: %w", err)
	}
	directory, err := os.Open(filepath.Dir(paths.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("open SSH directory for sync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return "", fmt.Errorf("sync SSH directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return "", fmt.Errorf("close SSH directory: %w", err)
	}
	return publicLine, nil
}

// NormalizePublicKey validates an Ed25519 public key and drops its comment.
func NormalizePublicKey(value string) (string, error) {
	if len(value) > 16<<10 {
		return "", errors.New("public key is too large")
	}
	fields := strings.Fields(value)
	if len(fields) < 2 || fields[0] != keyType {
		return "", errors.New("public key must be an ssh-ed25519 key")
	}
	wire, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("decode Ed25519 public key: %w", err)
	}
	if !validWireKey(wire) {
		return "", errors.New("invalid ssh-ed25519 public key")
	}
	for index := 2; index+1 < len(fields); index++ {
		if fields[index] == keyType {
			if _, err := base64.StdEncoding.DecodeString(fields[index+1]); err == nil {
				return "", errors.New("public key contains trailing key data")
			}
		}
	}
	return keyType + " " + base64.StdEncoding.EncodeToString(wire), nil
}

// Fingerprint derives the lowercase hexadecimal SHA-256 installation identity
// from the SSH public-key wire encoding.
func Fingerprint(publicKey string) (string, error) {
	normalized, err := NormalizePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	wire, _ := base64.StdEncoding.DecodeString(strings.Fields(normalized)[1])
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

// ShortFingerprint returns the conflict-filename identity segment.
func ShortFingerprint(publicKey string) (string, error) {
	fingerprint, err := Fingerprint(publicKey)
	if err != nil {
		return "", err
	}
	return fingerprint[:fingerprintBytes], nil
}

// AuthorizedLine composes the only supported sync grant.
func AuthorizedLine(peer, publicKey string) (string, error) {
	if err := peername.Validate(peer); err != nil {
		return "", err
	}
	normalized, err := NormalizePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	fingerprint, err := Fingerprint(normalized)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("command=\"%s serve --peer %s --fingerprint %s\",restrict %s %s%s", forcedBinary, peer, fingerprint, normalized, commentPrefix, peer), nil
}

// AddGrant idempotently installs peer's forced-command authorized_keys line.
// A known peer name with different key material is rejected.
func AddGrant(path, peer, publicKey string) error {
	return withAuthorizedLock(path, func() error { return addGrant(path, peer, publicKey) })
}

func addGrant(path, peer, publicKey string) error {
	line, err := AuthorizedLine(peer, publicKey)
	if err != nil {
		return err
	}
	contents, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read authorized_keys: %w", err)
	}
	for _, existing := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		if existing == line {
			return nil
		}
		if strings.HasSuffix(existing, " "+commentPrefix+peer) {
			return fmt.Errorf("peer %q already has a different authorized key", peer)
		}
		if existingKey, ok := publicKeyInAuthorizedLine(existing); ok && existingKey == normalizedFromLine(line) {
			return errors.New("public key already exists in an unmanaged or differently restricted authorized_keys line")
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), sshDirectoryMode); err != nil {
		return fmt.Errorf("create SSH directory: %w", err)
	}
	updated := append([]byte(nil), contents...)
	if len(updated) != 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	updated = append(updated, line...)
	updated = append(updated, '\n')
	return replaceFile(path, updated, authorizedMode)
}

// RemoveGrant removes only l2sync's line for peer.
func RemoveGrant(path, peer, publicKey string) error {
	return withAuthorizedLock(path, func() error { return removeGrant(path, peer, publicKey) })
}

func removeGrant(path, peer, publicKey string) error {
	if err := peername.Validate(peer); err != nil {
		return err
	}
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read authorized_keys: %w", err)
	}
	exact, err := AuthorizedLine(peer, publicKey)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if line == exact {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		return nil
	}
	updated := []byte(strings.Join(kept, "\n"))
	if len(updated) != 0 {
		updated = append(updated, '\n')
	}
	return replaceFile(path, updated, authorizedMode)
}

func marshalPublicKey(public ed25519.PublicKey) string {
	wire := make([]byte, 4+len(keyType)+4+len(public))
	binary.BigEndian.PutUint32(wire, uint32(len(keyType)))
	copy(wire[4:], keyType)
	offset := 4 + len(keyType)
	binary.BigEndian.PutUint32(wire[offset:], uint32(len(public)))
	copy(wire[offset+4:], public)
	return keyType + " " + base64.StdEncoding.EncodeToString(wire)
}

func validWireKey(wire []byte) bool {
	if len(wire) != 4+len(keyType)+4+ed25519.PublicKeySize {
		return false
	}
	nameSize := int(binary.BigEndian.Uint32(wire))
	if nameSize != len(keyType) || string(wire[4:4+nameSize]) != keyType {
		return false
	}
	offset := 4 + nameSize
	return int(binary.BigEndian.Uint32(wire[offset:])) == ed25519.PublicKeySize
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func validateCredentialDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SSH credential directory %q is not a real directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("SSH credential directory %q is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("SSH credential directory %q is group- or other-writable", path)
	}
	return nil
}

func validateCredentialFile(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential %q is not a regular file", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("credential %q is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("credential %q is writable by group or others", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private key %q is accessible by group or others", path)
	}
	return nil
}

func writeExclusive(path string, contents []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func replaceFile(path string, contents []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".authorized_keys-*")
	if err != nil {
		return fmt.Errorf("create temporary authorized_keys: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := bytes.NewReader(contents).WriteTo(temporary); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open SSH directory for sync: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync SSH directory: %w", err)
	}
	return nil
}

func withAuthorizedLock(path string, operation func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), sshDirectoryMode); err != nil {
		return fmt.Errorf("create SSH directory: %w", err)
	}
	if err := validateCredentialDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	lockPath := filepath.Join(filepath.Dir(path), ".l2sync-authorized_keys.lock")
	lockFD, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, privateKeyMode)
	if err != nil {
		return fmt.Errorf("open authorized_keys lock: %w", err)
	}
	lockFile := os.NewFile(uintptr(lockFD), lockPath)
	defer lockFile.Close()
	if err := validateOpenManagedFile(lockFile, lockPath, true); err != nil {
		return err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock authorized_keys: %w", err)
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	if err := validateAuthorizedKeys(path); err != nil {
		return err
	}
	return operation()
}

func validateAuthorizedKeys(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open authorized_keys safely: %w", err)
	}
	defer file.Close()
	return validateOpenManagedFile(file, path, false)
}

func validateOpenManagedFile(file *os.File, path string, private bool) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%q must be a regular file owned by the current user", path)
	}
	unsafeMask := fs.FileMode(0o022)
	if private {
		unsafeMask = 0o077
	}
	if info.Mode().Perm()&unsafeMask != 0 {
		return fmt.Errorf("%q has unsafe permissions %04o", path, info.Mode().Perm())
	}
	return nil
}

func publicKeyInAuthorizedLine(line string) (string, bool) {
	fields, err := authorizedTokens(line)
	if err != nil {
		return "", false
	}
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] != keyType {
			continue
		}
		normalized, err := NormalizePublicKey(fields[index] + " " + fields[index+1])
		return normalized, err == nil
	}
	return "", false
}

func authorizedTokens(line string) ([]string, error) {
	var tokens []string
	var token strings.Builder
	quoted := false
	escaped := false
	flush := func() {
		if token.Len() != 0 {
			tokens = append(tokens, token.String())
			token.Reset()
		}
	}
	for _, character := range line {
		if escaped {
			token.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' && quoted {
			escaped = true
			token.WriteRune(character)
			continue
		}
		if character == '"' {
			quoted = !quoted
			token.WriteRune(character)
			continue
		}
		if !quoted && (character == ' ' || character == '\t') {
			flush()
			continue
		}
		token.WriteRune(character)
	}
	if quoted || escaped {
		return nil, errors.New("unterminated authorized_keys option")
	}
	flush()
	return tokens, nil
}

func normalizedFromLine(line string) string {
	key, _ := publicKeyInAuthorizedLine(line)
	return key
}
