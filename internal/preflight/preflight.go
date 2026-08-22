//go:build linux

package preflight

import (
	"errors"
	"fmt"

	"l2syncd/internal/config"
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

	for name, peer := range cfg.Peers {
		if _, err := config.ResolvePeerAddress(peer); err != nil {
			return fmt.Errorf("resolve peer %q: %w", name, err)
		}
	}
	for name, mount := range cfg.Mounts {
		if _, ok := cfg.Peers[mount.Peer]; !ok {
			return fmt.Errorf("mount %q references unknown peer %q", name, mount.Peer)
		}
	}
	return nil
}
