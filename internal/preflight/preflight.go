package preflight

import (
	"fmt"
	"os"
	"path/filepath"

	"l2syncd/internal/config"
)

func Check(cfg config.Config) error {
	stateDir, err := config.StateDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("state directory is not writable: %w", err)
	}
	test, err := os.CreateTemp(stateDir, ".preflight-*")
	if err != nil {
		return fmt.Errorf("state directory is not writable: %w", err)
	}
	testName := test.Name()
	if err := test.Close(); err != nil {
		os.Remove(testName)
		return fmt.Errorf("close state preflight file: %w", err)
	}
	if err := os.Remove(testName); err != nil {
		return fmt.Errorf("remove state preflight file: %w", err)
	}

	for name, peer := range cfg.Peers {
		if filepath.IsAbs(peer.Addr) || peer.Addr == "" {
			return fmt.Errorf("peer %q has invalid address", name)
		}
	}
	for name, mount := range cfg.Mounts {
		if _, ok := cfg.Peers[mount.Peer]; !ok {
			return fmt.Errorf("mount %q references unknown peer %q", name, mount.Peer)
		}
	}
	return nil
}
