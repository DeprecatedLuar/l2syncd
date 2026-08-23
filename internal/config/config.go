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
	Peers    map[string]Peer     `toml:"peers"`
	Bindings map[string][]string `toml:"bindings"`
	Shared   map[string]string   `toml:"shared"`
	Remote   map[string]string   `toml:"remote"`
}

type Peer struct {
	Address   string `toml:"address"`
	Status    string `toml:"status"`
	PublicKey string `toml:"public_key,omitempty"`
}

// UnmarshalTOML accepts legacy string destinations as pending peers. Saving
// always emits the structured representation; loading alone never rewrites.
func (peer *Peer) UnmarshalTOML(value any) error {
	switch typed := value.(type) {
	case string:
		peer.Address = typed
		peer.Status = PeerPending
		return nil
	case map[string]any:
		for key := range typed {
			if key != "address" && key != "status" && key != "public_key" {
				return fmt.Errorf("unknown peer field %q", key)
			}
		}
		addressValue, addressExists := typed["address"]
		statusValue, statusExists := typed["status"]
		if !addressExists || !statusExists {
			return errors.New("structured peer entry requires address and status")
		}
		address, addressOK := addressValue.(string)
		status, statusOK := statusValue.(string)
		if !addressOK || !statusOK {
			return errors.New("peer address and status must be strings")
		}
		publicKey := ""
		if value, exists := typed["public_key"]; exists {
			var ok bool
			publicKey, ok = value.(string)
			if !ok {
				return errors.New("peer public_key must be a string")
			}
		}
		peer.Address, peer.Status, peer.PublicKey = address, status, publicKey
		return nil
	default:
		return fmt.Errorf("peer entry must be a destination string or table")
	}
}

const (
	PeerPending = "pending"
	PeerActive  = "active"
	PeerRevoked = "revoked"
)

func New() Config {
	return Config{
		Peers:    make(map[string]Peer),
		Bindings: make(map[string][]string),
		Shared:   make(map[string]string),
		Remote:   make(map[string]string),
	}
}

// Clone returns a deep copy suitable for change detection around mutations.
func Clone(cfg Config) Config {
	cloned := New()
	for name, peer := range cfg.Peers {
		cloned.Peers[name] = peer
	}
	for name, peers := range cfg.Bindings {
		cloned.Bindings[name] = append([]string(nil), peers...)
	}
	for name, path := range cfg.Shared {
		cloned.Shared[name] = path
	}
	for name, path := range cfg.Remote {
		cloned.Remote[name] = path
	}
	return cloned
}

// Equal compares the semantic configuration independent of TOML formatting.
func Equal(left, right Config) bool {
	if len(left.Peers) != len(right.Peers) || len(left.Bindings) != len(right.Bindings) || len(left.Shared) != len(right.Shared) || len(left.Remote) != len(right.Remote) {
		return false
	}
	for name, peer := range left.Peers {
		other, exists := right.Peers[name]
		if !exists || other != peer {
			return false
		}
	}
	for name, peers := range left.Bindings {
		other, exists := right.Bindings[name]
		if !exists || len(peers) != len(other) {
			return false
		}
		for index := range peers {
			if peers[index] != other[index] {
				return false
			}
		}
	}
	for name, path := range left.Shared {
		other, exists := right.Shared[name]
		if !exists || other != path {
			return false
		}
	}
	for name, path := range left.Remote {
		other, exists := right.Remote[name]
		if !exists || other != path {
			return false
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
			if knownStructuredPeerKey(key) {
				continue
			}
			keys = append(keys, key.String())
		}
		if len(keys) != 0 {
			return Config{}, fmt.Errorf("decode %s: unknown configuration keys: %s", path, strings.Join(keys, ", "))
		}
	}
	ensureMaps(&cfg)
	return cfg, nil
}

func knownStructuredPeerKey(key toml.Key) bool {
	if len(key) != 3 || key[0] != "peers" {
		return false
	}
	return key[2] == "address" || key[2] == "status" || key[2] == "public_key"
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
	if err := toml.NewEncoder(&contents).Encode(cfg); err != nil {
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
	if cfg.Bindings == nil {
		cfg.Bindings = make(map[string][]string)
	}
	if cfg.Shared == nil {
		cfg.Shared = make(map[string]string)
	}
	if cfg.Remote == nil {
		cfg.Remote = make(map[string]string)
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
