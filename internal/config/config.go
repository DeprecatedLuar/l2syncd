//go:build linux

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"github.com/kevinburke/ssh_config"
)

const (
	configDirectory = ".config/l2sync"
	configFilename  = "config.toml"
	stateDirectory  = ".local/state/l2sync"
	directoryMode   = 0o700
	fileMode        = 0o600
	preflightPrefix = ".l2sync-preflight-*"
)

var ErrNotFound = errors.New("configuration file does not exist")

type installedError struct{ err error }

func (err *installedError) Error() string { return err.err.Error() }
func (err *installedError) Unwrap() error { return err.err }

// WasInstalled reports that the atomic rename completed before a durability
// error. Callers must not compensate as though the old config were live.
func WasInstalled(err error) bool {
	var installed *installedError
	return errors.As(err, &installed)
}

type Config struct {
	Peers  map[string]Peer   `toml:"peers"`
	Shared map[string]Folder `toml:"shared"`
	Remote map[string]Folder `toml:"remote"`
}

// Peer is an SSH destination plus, once first contact has pinned it, the
// peer installation's public key. An empty PublicKey is the only
// representation of "bootstrap incomplete": trust-on-first-use is still
// permitted for this peer. A pinned key is never unpinned.
type Peer struct {
	Address   string `toml:"address"`
	PublicKey string `toml:"public_key,omitempty"`
}

// Folder is one registered directory. Which table it lives in is its role:
// Shared is owned locally and offered to peers, Remote is a replica joined
// from a peer. Peers stays a slice so a future multi-peer folder needs no
// schema change; v1 requires exactly one for Remote, at most one for Shared.
type Folder struct {
	Path  string   `toml:"path"`
	Peers []string `toml:"peers,omitempty"`
}

// Lookup returns the folder registered under name, from either table.
func (cfg Config) Lookup(name string) (Folder, bool) {
	if folder, exists := cfg.Shared[name]; exists {
		return folder, true
	}
	folder, exists := cfg.Remote[name]
	return folder, exists
}

// BoundPeer returns the single peer bound to name, if exactly one is.
func (cfg Config) BoundPeer(name string) (string, bool) {
	folder, exists := cfg.Lookup(name)
	if !exists || len(folder.Peers) != 1 {
		return "", false
	}
	return folder.Peers[0], true
}

func New() Config {
	return Config{
		Peers:  make(map[string]Peer),
		Shared: make(map[string]Folder),
		Remote: make(map[string]Folder),
	}
}

// Clone returns a deep copy suitable for change detection around mutations.
func Clone(cfg Config) Config {
	cloned := New()
	for name, peer := range cfg.Peers {
		cloned.Peers[name] = peer
	}
	for name, folder := range cfg.Shared {
		cloned.Shared[name] = Folder{Path: folder.Path, Peers: append([]string(nil), folder.Peers...)}
	}
	for name, folder := range cfg.Remote {
		cloned.Remote[name] = Folder{Path: folder.Path, Peers: append([]string(nil), folder.Peers...)}
	}
	return cloned
}

// Equal compares the semantic configuration independent of TOML formatting.
func Equal(left, right Config) bool {
	if len(left.Peers) != len(right.Peers) || len(left.Shared) != len(right.Shared) || len(left.Remote) != len(right.Remote) {
		return false
	}
	for name, peer := range left.Peers {
		other, exists := right.Peers[name]
		if !exists || other != peer {
			return false
		}
	}
	if !equalFolders(left.Shared, right.Shared) || !equalFolders(left.Remote, right.Remote) {
		return false
	}
	return true
}

func equalFolders(left, right map[string]Folder) bool {
	for name, folder := range left {
		other, exists := right[name]
		if !exists || folder.Path != other.Path || len(folder.Peers) != len(other.Peers) {
			return false
		}
		for index := range folder.Peers {
			if folder.Peers[index] != other.Peers[index] {
				return false
			}
		}
	}
	return true
}

func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}

	return LoadFile(path)
}

// LoadFile decodes an explicit config path without changing it.
func LoadFile(path string) (Config, error) {
	var cfg Config
	metadata, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(), ErrNotFound
		}
		return Config{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return Config{}, fmt.Errorf("decode %s: unknown configuration keys: %s", path, strings.Join(keys, ", "))
	}
	ensureMaps(&cfg)
	return cfg, nil
}

// Replace atomically installs already-validated configuration bytes.
func Replace(contents []byte) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), directoryMode); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if err := syncConfigDirectory(filepath.Dir(path)); err != nil {
		return &installedError{err: err}
	}
	return nil
}

func syncConfigDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}

func Save(cfg Config) error {
	var contents bytes.Buffer
	encoder := toml.NewEncoder(&contents)
	encoder.Indent = ""
	if err := encoder.Encode(cfg); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return Replace(contents.Bytes())
}

func Path() (string, error) {
	base, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	if override := os.Getenv("XDG_CONFIG_HOME"); override != "" {
		return filepath.Join(override, "l2sync", configFilename), nil
	}
	return filepath.Join(base, configDirectory, configFilename), nil
}

func StateDir() (string, error) {
	base, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	if override := os.Getenv("XDG_STATE_HOME"); override != "" {
		return filepath.Join(override, "l2sync"), nil
	}
	return filepath.Join(base, stateDirectory), nil
}

// CheckStateDirWritable verifies that the state directory, or the closest
// existing parent when it has not been created yet, is writable. It never
// creates the directory.
func CheckStateDirWritable() error {
	stateDir, err := StateDir()
	if err != nil {
		return err
	}
	parent, err := existingParent(stateDir)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	temporary, err := os.CreateTemp(parent, preflightPrefix)
	if err != nil {
		return fmt.Errorf("state directory is not writable: %w", err)
	}
	temporaryName := temporary.Name()
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("close state preflight file: %w", err)
	}
	if err := os.Remove(temporaryName); err != nil {
		return fmt.Errorf("remove state preflight file: %w", err)
	}
	return nil
}

// ResolvePeerAddress returns the SSH HostName for peer when it is configured,
// or its configured address when no matching SSH configuration exists.
func ResolvePeerAddress(address string) (string, error) {
	if err := ValidatePeerAddress(address); err != nil {
		return "", err
	}
	if strings.ContainsAny(address, "@:") {
		return address, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	sshConfigPath := filepath.Join(home, ".ssh", "config")
	sshConfig, err := os.Open(sshConfigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return address, nil
		}
		return "", fmt.Errorf("open SSH config: %w", err)
	}
	defer sshConfig.Close()

	parsed, err := ssh_config.Decode(sshConfig)
	if err != nil {
		return "", fmt.Errorf("parse SSH config: %w", err)
	}
	// Parsing validates the file. Return the original alias so OpenSSH still
	// applies every option in its matching Host block (User, Port, ProxyJump,
	// IdentityFile, and others), not only HostName.
	_ = parsed
	return address, nil
}

// ValidatePeerAddress rejects values that OpenSSH could interpret as options
// or that cannot be one destination argv element.
func ValidatePeerAddress(address string) error {
	if address == "" {
		return errors.New("peer address is empty")
	}
	if strings.HasPrefix(address, "-") {
		return errors.New("peer address must not begin with '-'")
	}
	for _, character := range address {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return errors.New("peer address contains whitespace or control characters")
		}
	}
	return nil
}

func ensureMaps(cfg *Config) {
	if cfg.Peers == nil {
		cfg.Peers = make(map[string]Peer)
	}
	if cfg.Shared == nil {
		cfg.Shared = make(map[string]Folder)
	}
	if cfg.Remote == nil {
		cfg.Remote = make(map[string]Folder)
	}
}

func existingParent(path string) (string, error) {
	for {
		info, err := os.Stat(path)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("%q is not a directory", path)
			}
			return path, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", fmt.Errorf("no existing parent for %q", path)
		}
		path = parent
	}
}
