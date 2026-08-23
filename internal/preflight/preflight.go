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
		if peer.Status != config.PeerPending && peer.Status != config.PeerActive && peer.Status != config.PeerRevoked {
			return fmt.Errorf("peer %q has invalid status %q", name, peer.Status)
		}
		if (peer.Status == config.PeerActive || peer.Status == config.PeerRevoked) && peer.PublicKey == "" {
			return fmt.Errorf("active peer %q has no public key", name)
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
	for folder, peers := range cfg.Bindings {
		if err := sharename.Validate(folder); err != nil {
			return fmt.Errorf("binding folder %q: %w", folder, err)
		}
		if len(peers) != 1 {
			return fmt.Errorf("folder %q must bind exactly one peer", folder)
		}
		peer, exists := cfg.Peers[peers[0]]
		if !exists {
			return fmt.Errorf("folder %q binds unknown peer %q", folder, peers[0])
		}
		if peer.Status == config.PeerRevoked {
			return fmt.Errorf("folder %q binds revoked peer %q", folder, peers[0])
		}
		if _, shared := cfg.Shared[folder]; !shared {
			if _, remote := cfg.Remote[folder]; !remote {
				return fmt.Errorf("binding names unregistered folder %q", folder)
			}
		}
	}
	for name, path := range cfg.Shared {
		if err := sharename.Validate(name); err != nil {
			return fmt.Errorf("shared folder %q: %w", name, err)
		}
		if _, exists := cfg.Remote[name]; exists {
			return fmt.Errorf("folder %q is registered as both shared and remote", name)
		}
		if err := validateFolder(name, path); err != nil {
			return fmt.Errorf("shared folder %q: %w", name, err)
		}
	}
	for name, path := range cfg.Remote {
		if err := sharename.Validate(name); err != nil {
			return fmt.Errorf("remote folder %q: %w", name, err)
		}
		if err := validateFolder(name, path); err != nil {
			return fmt.Errorf("remote folder %q: %w", name, err)
		}
		bound := cfg.Bindings[name]
		if len(bound) != 1 {
			return fmt.Errorf("remote folder %q must bind exactly one peer", name)
		}
		peer, exists := cfg.Peers[bound[0]]
		if !exists || peer.Status != config.PeerPending && peer.Status != config.PeerActive {
			return fmt.Errorf("remote folder %q binds unavailable peer %q", name, bound[0])
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
