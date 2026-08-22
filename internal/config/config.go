//go:build linux

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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

type Config struct {
	Peers  map[string]Peer  `toml:"peers"`
	Shares map[string]Share `toml:"shares"`
	Mounts map[string]Mount `toml:"mounts"`
}

type Peer struct {
	Addr string `toml:"addr"`
}

type Share struct {
	Local  string   `toml:"local"`
	Ignore []string `toml:"ignore"`
}

type Mount struct {
	Peer  string `toml:"peer"`
	Local string `toml:"local"`
}

func New() Config {
	return Config{
		Peers:  make(map[string]Peer),
		Shares: make(map[string]Share),
		Mounts: make(map[string]Mount),
	}
}

func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return New(), ErrNotFound
		}
		return Config{}, fmt.Errorf("decode %s: %w", path, err)
	}
	ensureMaps(&cfg)
	return cfg, nil
}

func Save(cfg Config) error {
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
	if err := toml.NewEncoder(temporary).Encode(cfg); err != nil {
		temporary.Close()
		return fmt.Errorf("encode config: %w", err)
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
	return nil
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
func ResolvePeerAddress(peer Peer) (string, error) {
	if peer.Addr == "" {
		return "", errors.New("peer address is empty")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	sshConfigPath := filepath.Join(home, ".ssh", "config")
	sshConfig, err := os.Open(sshConfigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return peer.Addr, nil
		}
		return "", fmt.Errorf("open SSH config: %w", err)
	}
	defer sshConfig.Close()

	parsed, err := ssh_config.Decode(sshConfig)
	if err != nil {
		return "", fmt.Errorf("parse SSH config: %w", err)
	}
	hostname, err := parsed.Get(peer.Addr, "HostName")
	if err != nil {
		return "", fmt.Errorf("resolve SSH host %q: %w", peer.Addr, err)
	}
	if hostname == "" {
		return peer.Addr, nil
	}
	return hostname, nil
}

func ensureMaps(cfg *Config) {
	if cfg.Peers == nil {
		cfg.Peers = make(map[string]Peer)
	}
	if cfg.Shares == nil {
		cfg.Shares = make(map[string]Share)
	}
	if cfg.Mounts == nil {
		cfg.Mounts = make(map[string]Mount)
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
