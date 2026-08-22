//go:build linux

package preflight

import (
	"errors"
	"fmt"
	"os"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
)

// LoadConfig loads configuration and verifies it is safe to use.
func LoadConfig() (config.Config, error) {
	cfg, err := config.Load()
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		return config.Config{}, fmt.Errorf("invalid config: %w", err)
	}
	if errors.Is(err, config.ErrNotFound) {
		cfg = config.New()
	}
	if err := Check(cfg); err != nil {
		return config.Config{}, fmt.Errorf("preflight failed: %w", err)
	}
	return cfg, nil
}

func Check(cfg config.Config) error {
	if err := config.CheckStateDirWritable(); err != nil {
		return err
	}
	return Validate(cfg)
}

// Validate checks configuration relationships and managed-folder identities.
// It does not inspect the state directory, which lets config editing validate
// the edited document before the next command runs.
func Validate(cfg config.Config) error {

	for name, peer := range cfg.Peers {
		if _, err := config.ResolvePeerAddress(peer); err != nil {
			return fmt.Errorf("resolve peer %q: %w", name, err)
		}
	}
	for name, path := range cfg.Shared {
		if _, exists := cfg.Remote[name]; exists {
			return fmt.Errorf("folder %q is registered as both shared and remote", name)
		}
		if err := validateFolder(name, path); err != nil {
			return fmt.Errorf("shared folder %q: %w", name, err)
		}
	}
	for name, path := range cfg.Remote {
		if err := validateFolder(name, path); err != nil {
			return fmt.Errorf("remote folder %q: %w", name, err)
		}
	}
	return nil
}

func validateFolder(name, path string) error {
	if name == "" || path == "" {
		return fmt.Errorf("name and path are required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return err
	}
	if marker.Name != name {
		return fmt.Errorf("marker names folder %q, want %q", marker.Name, name)
	}
	return nil
}
