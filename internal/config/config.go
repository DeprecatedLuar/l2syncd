package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	configDirectory = ".config/l2sync"
	configFilename  = "config.toml"
	stateDirectory  = ".local/state/l2sync"
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
	Local string `toml:"local"`
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
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	if err := temporary.Chmod(0o600); err != nil {
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
