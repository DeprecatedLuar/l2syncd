//go:build linux

package preflight

import (
	"errors"
	"fmt"
	"os"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/peername"
	"l2syncd/internal/sharename"
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
	peerKeys := make(map[string]string)
	for name, peer := range cfg.Peers {
		if err := peername.Validate(name); err != nil {
			return fmt.Errorf("peer %q: %w", name, err)
		}
		if peer.PublicKey != "" {
			normalized, err := connection.NormalizePublicKey(peer.PublicKey)
			if err != nil {
				return fmt.Errorf("peer %q public key: %w", name, err)
			}
			if other, exists := peerKeys[normalized]; exists {
				return fmt.Errorf("peers %q and %q use the same public key", other, name)
			}
			peerKeys[normalized] = name
		}
		if _, err := config.ResolvePeerAddress(peer.Address); err != nil {
			return fmt.Errorf("resolve peer %q: %w", name, err)
		}
	}
	for name, folder := range cfg.Shared {
		if err := sharename.Validate(name); err != nil {
			return fmt.Errorf("shared folder %q: %w", name, err)
		}
		if _, exists := cfg.Remote[name]; exists {
			return fmt.Errorf("folder %q is registered as both shared and remote", name)
		}
		if err := validateFolder(name, folder.Path); err != nil {
			return fmt.Errorf("shared folder %q: %w", name, err)
		}
		if len(folder.Peers) > 1 {
			return fmt.Errorf("folder %q must bind exactly one peer", name)
		}
		if len(folder.Peers) == 1 {
			if _, exists := cfg.Peers[folder.Peers[0]]; !exists {
				return fmt.Errorf("folder %q binds unknown peer %q", name, folder.Peers[0])
			}
		}
	}
	for name, folder := range cfg.Remote {
		if err := sharename.Validate(name); err != nil {
			return fmt.Errorf("remote folder %q: %w", name, err)
		}
		if err := validateFolder(name, folder.Path); err != nil {
			return fmt.Errorf("remote folder %q: %w", name, err)
		}
		if len(folder.Peers) != 1 {
			return fmt.Errorf("remote folder %q must bind exactly one peer", name)
		}
		if _, exists := cfg.Peers[folder.Peers[0]]; !exists {
			return fmt.Errorf("remote folder %q binds unavailable peer %q", name, folder.Peers[0])
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
