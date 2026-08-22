//go:build linux

package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"l2syncd/internal/apply"
	"l2syncd/internal/config"
	"l2syncd/internal/engine"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
	"l2syncd/internal/scan"
	"l2syncd/internal/state"
	"l2syncd/internal/transport"
)

const (
	nowExitOK          = 0
	nowExitError       = 1
	nowExitInvalid     = 2
	nowExitUnreachable = 3
)

func Now(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync now")
		return nowExitError
	}
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return nowExitInvalid
	}
	for name, path := range cfg.Remote {
		if err := planRemote(context.Background(), cfg, name, path, stdout); err != nil {
			fmt.Fprintf(stderr, "l2sync: now %q: %v\n", name, err)
			if isTransportError(err) {
				return nowExitUnreachable
			}
			return nowExitError
		}
	}
	return nowExitOK
}

func planRemote(ctx context.Context, cfg config.Config, name, path string, stdout io.Writer) error {
	marker, err := guard.ReadMarker(path)
	if err != nil {
		return fmt.Errorf("read marker: %w", err)
	}
	provider, address, err := findProvider(ctx, cfg, name)
	if err != nil {
		return err
	}
	remoteFiles, err := transport.ListFiles(ctx, address, name)
	if err != nil {
		return fmt.Errorf("peer %q listing: %w", provider, err)
	}
	localBaseline, err := loadBaseline(name)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	local, err := scanShare(path, localBaseline, marker.Ignore)
	if err != nil {
		return err
	}
	remote := state.New()
	for _, file := range remoteFiles {
		remote.Files[file.Path] = state.File{Hash: file.Hash, Size: file.Size}
	}
	plan := engine.PlanStates("local", local.Snapshot, provider, remote, localBaseline)
	if plan.Halted {
		return fmt.Errorf("halted: %s", plan.Reason)
	}
	for _, action := range plan.Actions {
		if err := applyAction(ctx, action, name, path, provider, address, local.Snapshot, remote); err != nil {
			return err
		}
	}
	if len(plan.Actions) > 0 {
		result, err := scanShare(path, localBaseline, marker.Ignore)
		if err != nil {
			return fmt.Errorf("rescan after apply: %w", err)
		}
		if err := state.Save(name, result.Snapshot); err != nil {
			return fmt.Errorf("save baseline: %w", err)
		}
	}
	return nil
}

func applyAction(ctx context.Context, action engine.Action, share, root, provider, address string, local, remote state.Baseline) error {
	remoteFile := remote.Files[action.Path]
	remoteSource := action.Source == provider || action.Winner == provider
	switch action.Kind {
	case engine.Pull, engine.Resurrect:
		if !remoteSource {
			return fmt.Errorf("cannot apply local source action %s for %q", action.Kind, action.Path)
		}
		data, err := transport.ReadFile(ctx, address, share, action.Path, remoteFile.Hash)
		if err != nil {
			return fmt.Errorf("read %q from peer: %w", action.Path, err)
		}
		return apply.Write(root, action.Path, bytes.NewReader(data), remoteFile.Hash)
	case engine.Delete:
		if remoteSource {
			return apply.Delete(root, action.Path)
		}
		return transport.DeleteFile(ctx, address, share, action.Path)
	case engine.Conflict:
		if remoteSource {
			if err := apply.PreserveConflict(root, action.Path, provider); err != nil {
				return err
			}
			data, err := transport.ReadFile(ctx, address, share, action.Path, remoteFile.Hash)
			if err != nil {
				return fmt.Errorf("read conflict winner %q from peer: %w", action.Path, err)
			}
			return apply.Write(root, action.Path, bytes.NewReader(data), remoteFile.Hash)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(action.Path)))
		if err != nil {
			return fmt.Errorf("read local conflict winner %q: %w", action.Path, err)
		}
		losing, err := transport.ReadFile(ctx, address, share, action.Path, remoteFile.Hash)
		if err != nil {
			return fmt.Errorf("read conflict loser %q from peer: %w", action.Path, err)
		}
		if err := apply.WriteConflictCopy(root, action.Path, provider, bytes.NewReader(losing), remoteFile.Hash); err != nil {
			return fmt.Errorf("preserve conflict loser %q locally: %w", action.Path, err)
		}
		if err := transport.WriteConflictFile(ctx, address, share, action.Path, data, local.Files[action.Path].Hash, provider); err != nil {
			return fmt.Errorf("write conflict winner %q to peer: %w", action.Path, err)
		}
		return nil
	case engine.Push:
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(action.Path)))
		if err != nil {
			return fmt.Errorf("read local file %q: %w", action.Path, err)
		}
		if err := transport.WriteFile(ctx, address, share, action.Path, data, local.Files[action.Path].Hash); err != nil {
			return fmt.Errorf("write %q to peer: %w", action.Path, err)
		}
		return nil
	default:
		return fmt.Errorf("unknown action %q", action.Kind)
	}
}

func scanShare(path string, baseline state.Baseline, ignore []string) (scan.Result, error) {
	result, err := scan.DetectWithIgnore(path, baseline, ignore)
	if err != nil {
		return scan.Result{}, fmt.Errorf("scan share: %w", err)
	}
	return result, nil
}

func findProvider(ctx context.Context, cfg config.Config, name string) (string, string, error) {
	providers := make([]string, 0, 1)
	addresses := make(map[string]string)
	for peerName, peer := range cfg.Peers {
		address, err := config.ResolvePeerAddress(peer)
		if err != nil {
			return "", "", fmt.Errorf("resolve peer %q: %w", peerName, err)
		}
		shares, err := transport.ListShares(ctx, address)
		if err != nil {
			return "", "", fmt.Errorf("peer %q unreachable: %w", peerName, err)
		}
		if contains(shares, name) {
			providers = append(providers, peerName)
			addresses[peerName] = address
		}
	}
	if len(providers) == 0 {
		return "", "", fmt.Errorf("no peer offers folder %q", name)
	}
	if len(providers) != 1 {
		return "", "", fmt.Errorf("multiple peers offer folder %q", name)
	}
	return providers[0], addresses[providers[0]], nil
}

func isTransportError(err error) bool {
	return err != nil
}
