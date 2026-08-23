//go:build linux

package commands

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"unicode"

	"l2syncd/internal/config"
	connectionpkg "l2syncd/internal/connection"
	"l2syncd/internal/peername"
	"l2syncd/internal/transport"
)

const (
	connectionExitOK    = 0
	connectionExitError = 1
	connectionSSH       = "ssh"
	connectionBinary    = "l2sync"
)

var (
	connectionProbe    = probeExistingAccess
	connectionInstall  = installRemoteGrant
	connectionExchange = transport.Exchange
	connectionConfirm  = confirmInstall
	loginShell         = currentLoginShell
)

// Connection dispatches peer credential management commands.
func Connection(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: l2sync connection <add|ls|rm|edit>")
		return connectionExitError
	}
	switch args[0] {
	case "add":
		return connectionAdd(args[1:], os.Stdin, stdout, stderr)
	case "ls", "list":
		return connectionList(args[1:], stdout, stderr)
	case "rm", "remove":
		return connectionRemove(args[1:], stderr)
	case "edit":
		return ConfigEdit(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "l2sync: unknown connection command %q\n", args[0])
		return connectionExitError
	}
}

func connectionAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name, address, suppliedKey, err := parseConnectionAdd(args, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	if existing, found := cfg.Peers[name]; found {
		if existing.Status == config.PeerRevoked {
			fmt.Fprintf(stderr, "l2sync: peer %q removal is incomplete; retry connection rm before re-adding\n", name)
			return connectionExitError
		}
		if existing.Address != address || suppliedKey != "" && existing.PublicKey != "" && existing.PublicKey != suppliedKey {
			fmt.Fprintf(stderr, "l2sync: peer %q already exists with different connection data\n", name)
			return connectionExitError
		}
		if suppliedKey == "" && existing.Status == config.PeerActive {
			if err := storePeerLocked(name, existing); err != nil {
				fmt.Fprintf(stderr, "l2sync: verify active peer: %v\n", err)
				return connectionExitError
			}
			return connectionExitOK
		}
	}
	if suppliedKey != "" {
		if err := rejectDuplicatePeerKey(cfg, name, suppliedKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: %v\n", err)
			return connectionExitError
		}
		paths, localKey, ok := resolveLocalKey(stderr, "load")
		if !ok {
			return connectionExitError
		}
		if localKey == suppliedKey {
			fmt.Fprintln(stderr, "l2sync: peer public key is this installation's key")
			return connectionExitError
		}
		status := config.PeerPending
		if existing, exists := cfg.Peers[name]; exists && existing.Status == config.PeerActive {
			status = config.PeerActive
		}
		cfg.Peers[name] = config.Peer{Address: address, Status: status, PublicKey: suppliedKey}
		if err := storePeerLocked(name, cfg.Peers[name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
			return connectionExitError
		}
		if err := connectionpkg.AddGrant(paths.AuthorizedKeys, name, suppliedKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: install restricted grant: %v (peer remains pending)\n", err)
			return connectionExitError
		}
		if shell, err := loginShell(); err == nil && filepath.Base(shell) == "bash" {
			fmt.Fprintf(stderr, "l2sync: warning: login shell %q sources startup files before SSH forced commands; use a dedicated sync account for hardened isolation\n", shell)
		}
		return connectionExitOK
	}

	_, localKey, ok := resolveLocalKey(stderr, "prepare")
	if !ok {
		return connectionExitError
	}
	resolved, err := config.ResolvePeerAddress(address)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve destination: %v\n", err)
		return connectionExitError
	}
	available := connectionProbe(context.Background(), resolved) == nil
	if !available {
		cfg.Peers[name] = config.Peer{Address: address, Status: config.PeerPending}
		if err := storePeerLocked(name, cfg.Peers[name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
			return connectionExitError
		}
		localName, localAddress := installationAddress()
		fmt.Fprintf(stdout, "No existing SSH access to %s.\nSend this to whoever runs that machine:\n\n  l2sync connection add %s %s --key %q\n\nPeer %q saved as pending.\n", resolved, localName, localAddress, localKey, name)
		return connectionExitOK
	}
	confirmed, err := connectionConfirm(stdin, stdout, name)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: read confirmation: %v\n", err)
		return connectionExitError
	}
	if !confirmed {
		fmt.Fprintln(stderr, "l2sync: key installation cancelled")
		return connectionExitError
	}
	peer := config.Peer{Address: address, Status: config.PeerPending}
	cfg.Peers[name] = peer
	if err := storePeerLocked(name, peer); err != nil {
		fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
		return connectionExitError
	}
	localName, localAddress := installationAddress()
	if err := connectionInstall(context.Background(), resolved, localName, localAddress, localKey); err != nil {
		fmt.Fprintf(stderr, "l2sync: install remote restricted grant: %v\n", err)
		return connectionExitError
	}
	endpoint, err := endpointForPeer(name, peer, func(publicKey string) error {
		if err := rejectDuplicatePeerKey(cfg, name, publicKey); err != nil {
			return err
		}
		peer.PublicKey = publicKey
		peer.Status = config.PeerActive
		cfg.Peers[name] = peer
		return storePeerLocked(name, peer)
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: prepare peer handshake: %v\n", err)
		return connectionExitError
	}
	if err := connectionExchange(context.Background(), endpoint); err != nil {
		fmt.Fprintf(stderr, "l2sync: peer handshake: %v\n", err)
		return connectionExitError
	}
	return connectionExitOK
}

// resolveLocalKey resolves this installation's key paths and ensures its
// key pair exists, writing an error to stderr and reporting failure on the
// caller's behalf. verb names the EnsureKey step in the error message
// (e.g. "load", "prepare").
func resolveLocalKey(stderr io.Writer, verb string) (connectionpkg.Paths, string, bool) {
	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve installation key: %v\n", err)
		return connectionpkg.Paths{}, "", false
	}
	localKey, err := connectionpkg.EnsureKey(paths)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %s installation key: %v\n", verb, err)
		return connectionpkg.Paths{}, "", false
	}
	return paths, localKey, true
}

func storePeerLocked(name string, peer config.Peer) error {
	return updateConfigLocked(func(current *config.Config) error {
		if err := rejectDuplicatePeerKey(*current, name, peer.PublicKey); peer.PublicKey != "" && err != nil {
			return err
		}
		if existing, exists := current.Peers[name]; exists {
			if existing.Status == config.PeerRevoked {
				return fmt.Errorf("peer %q is revoked", name)
			}
			if existing.Address != peer.Address {
				return fmt.Errorf("peer %q address changed concurrently", name)
			}
			if existing.PublicKey != "" && peer.PublicKey != "" && existing.PublicKey != peer.PublicKey {
				return fmt.Errorf("peer %q public key changed concurrently", name)
			}
			if existing.Status == config.PeerActive && peer.Status != config.PeerActive {
				return fmt.Errorf("peer %q cannot transition from active to %s", name, peer.Status)
			}
		}
		current.Peers[name] = peer
		return nil
	})
}

func connectionList(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync connection ls")
		return connectionExitError
	}
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	names := sortedKeys(cfg.Peers)
	for _, name := range names {
		peer := cfg.Peers[name]
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", name, peer.Status, peer.Address)
	}
	return connectionExitOK
}

func connectionRemove(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: l2sync connection rm <name>")
		return connectionExitError
	}
	name := args[0]
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	peer, exists := cfg.Peers[name]
	if !exists {
		fmt.Fprintf(stderr, "l2sync: peer %q not found\n", name)
		return connectionExitError
	}
	for folder, peers := range cfg.Bindings {
		if len(peers) == 1 && peers[0] == name {
			fmt.Fprintf(stderr, "l2sync: peer %q is still bound to folder %q\n", name, folder)
			return connectionExitError
		}
	}
	if err := updateConfigLocked(func(current *config.Config) error {
		latest, exists := current.Peers[name]
		if !exists {
			return fmt.Errorf("peer %q was removed concurrently", name)
		}
		if latest.PublicKey != peer.PublicKey || latest.Address != peer.Address {
			return fmt.Errorf("peer %q changed during removal", name)
		}
		for folder, peers := range current.Bindings {
			if len(peers) == 1 && peers[0] == name {
				return fmt.Errorf("peer %q is still bound to folder %q", name, folder)
			}
		}
		latest.Status = config.PeerRevoked
		current.Peers[name] = latest
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "l2sync: revoke peer entry: %v\n", err)
		return connectionExitError
	}
	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: peer revoked, but resolve authorized_keys: %v\n", err)
		return connectionExitError
	}
	if peer.PublicKey == "" {
		return removeRevokedPeer(name, peer, stderr)
	}
	if err := connectionpkg.RemoveGrant(paths.AuthorizedKeys, name, peer.PublicKey); err != nil {
		fmt.Fprintf(stderr, "l2sync: peer revoked, but remove restricted grant: %v; retry connection rm\n", err)
		return connectionExitError
	}
	return removeRevokedPeer(name, peer, stderr)
}

func removeRevokedPeer(name string, peer config.Peer, stderr io.Writer) int {
	if err := updateConfigLocked(func(current *config.Config) error {
		latest, exists := current.Peers[name]
		if !exists {
			return nil
		}
		if latest.Status != config.PeerRevoked || latest.PublicKey != peer.PublicKey || latest.Address != peer.Address {
			return fmt.Errorf("peer %q changed after revocation", name)
		}
		delete(current.Peers, name)
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "l2sync: restricted grant removed, but remove revoked peer entry: %v\n", err)
		return connectionExitError
	}
	return connectionExitOK
}

func parseConnectionAdd(args []string, stdin io.Reader) (string, string, string, error) {
	if len(args) < 1 {
		return "", "", "", errors.New("usage: l2sync connection add <name> [destination] [--key <pubkey>]")
	}
	name := strings.ToLower(args[0])
	if err := peername.Validate(name); err != nil {
		return "", "", "", err
	}
	address := name
	var key string
	position := 1
	if position < len(args) && args[position] != "--key" {
		address = args[position]
		position++
	}
	if position < len(args) {
		if args[position] != "--key" || position+2 != len(args) {
			return "", "", "", errors.New("usage: l2sync connection add <name> [destination] [--key <pubkey>]")
		}
		key = args[position+1]
		if key == "-" {
			contents, err := io.ReadAll(io.LimitReader(stdin, 16<<10))
			if err != nil {
				return "", "", "", fmt.Errorf("read public key: %w", err)
			}
			key = string(contents)
		}
		normalized, err := connectionpkg.NormalizePublicKey(key)
		if err != nil {
			return "", "", "", err
		}
		key = normalized
	}
	if err := config.ValidatePeerAddress(address); err != nil {
		return "", "", "", fmt.Errorf("invalid SSH destination: %w", err)
	}
	return name, address, key, nil
}

func loadConfigWithoutFolderPreflight() (config.Config, error) {
	cfg, err := config.Load()
	if errors.Is(err, config.ErrNotFound) {
		return config.New(), nil
	}
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func rejectDuplicatePeerKey(cfg config.Config, name, publicKey string) error {
	normalized, err := connectionpkg.NormalizePublicKey(publicKey)
	if err != nil {
		return err
	}
	for other, peer := range cfg.Peers {
		if other == name || peer.PublicKey == "" {
			continue
		}
		candidate, err := connectionpkg.NormalizePublicKey(peer.PublicKey)
		if err == nil && candidate == normalized {
			return fmt.Errorf("public key is already registered as peer %q", other)
		}
	}
	return nil
}

func probeExistingAccess(ctx context.Context, destination string) error {
	cmd := exec.CommandContext(ctx, connectionSSH, "-T", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", destination, "true")
	return cmd.Run()
}

func installRemoteGrant(ctx context.Context, destination, localName, localAddress, publicKey string) error {
	if err := peername.Validate(localName); err != nil {
		return err
	}
	if !safeBootstrapAddress(localAddress) {
		return errors.New("local bootstrap address contains unsafe characters")
	}
	cmd := exec.CommandContext(ctx, connectionSSH, "-T", "-o", "ControlMaster=no", "-o", "ControlPath=none", destination, connectionBinary, "connection", "add", localName, localAddress, "--key", "-")
	cmd.Stdin = strings.NewReader(publicKey + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remote connection add: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func confirmInstall(input io.Reader, output io.Writer, name string) (bool, error) {
	fmt.Fprintf(output, "Install l2sync sync key on %s? [y/N] ", name)
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func installationAddress() (string, string) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	name = strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, name)
	return name, host
}

func safeBootstrapAddress(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("@._:-", character)) {
			return false
		}
	}
	return true
}

func currentLoginShell() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", err
	}
	contents, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == current.Username {
			return fields[6], nil
		}
	}
	return "", errors.New("current account is absent from /etc/passwd")
}
