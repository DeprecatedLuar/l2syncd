//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

const (
	returnDialWait   = 30 * time.Second
	sshConnectionEnv = "SSH_CONNECTION"
	maxReturnPort    = 65535
)

var returnDial = transport.Exchange

// verifyReturnRoute stores how to reach peerName (the source address of the
// SSH connection it arrived on, unless route overrides the host), pins its
// host keys, and dials back. Any failure restores the previous address and
// pins.
func verifyReturnRoute(ctx context.Context, peerName, fingerprint string, route transport.ReturnRoute, sshConnection string) error {
	rawHost, err := returnHost(route, sshConnection)
	if err != nil {
		return err
	}
	host, err := config.NormalizeHost(rawHost)
	if err != nil {
		return fmt.Errorf("return host: %w", err)
	}
	if route.User == "" || strings.ContainsAny(route.User, "@ \t") {
		return fmt.Errorf("invalid return user %q", route.User)
	}
	if route.Port < 1 || route.Port > maxReturnPort {
		return fmt.Errorf("invalid return port %d", route.Port)
	}
	if len(route.HostKeys) == 0 {
		return errors.New("return route carries no host keys")
	}
	address := route.User + "@" + host
	if err := config.ValidatePeerAddress(address); err != nil {
		return fmt.Errorf("return address: %w", err)
	}
	port := route.Port
	if port == config.DefaultSSHPort {
		port = 0
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		return err
	}
	previousPins, err := connection.HostKeysFor(paths.KnownHosts, host, port)
	if err != nil {
		return err
	}
	var previous config.Peer
	if err := updateConfigLocked(func(current *config.Config) error {
		peer, exists := current.Peers[peerName]
		if !exists || peer.PublicKey == "" {
			return fmt.Errorf("peer %q has no configured public key", peerName)
		}
		if err := requireAuthenticatedFingerprint(peer, fingerprint); err != nil {
			return fmt.Errorf("peer %q authorization changed: %w", peerName, err)
		}
		if other, used := peerUsingEndpoint(current, peerName, host, port); used {
			return fmt.Errorf("return route %s port %d is already used by peer %q", host, route.Port, other)
		}
		previous = peer
		peer.Address, peer.Port = address, port
		current.Peers[peerName] = peer
		return nil
	}); err != nil {
		return err
	}
	revert := func(cause error) error {
		restorePins := connection.UnpinHostKeys(paths.KnownHosts, host, port)
		if len(previousPins) > 0 {
			restorePins = connection.PinHostKeys(paths.KnownHosts, host, port, previousPins)
		}
		return errors.Join(cause, restorePins, restorePeerRoute(peerName, previous, address, port))
	}
	if err := connection.PinHostKeys(paths.KnownHosts, host, port, route.HostKeys); err != nil {
		return revert(err)
	}
	updated := previous
	updated.Address, updated.Port = address, port
	endpoint, err := endpointForPeer(peerName, updated, nil)
	if err != nil {
		return revert(err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, returnDialWait)
	defer cancel()
	if err := returnDial(dialCtx, endpoint); err != nil {
		return revert(fmt.Errorf("dial back %s port %d: %w", address, route.Port, err))
	}
	return removeStalePins(paths.KnownHosts, peerName, previous, host, port)
}

// removeStalePins unpins the host:port previous pointed at, unless it is the
// route just stored or another peer still uses it.
func removeStalePins(knownHosts, peerName string, previous config.Peer, host string, port int) error {
	if previous.Address == "" {
		return nil
	}
	previousHost, pinned := pinnedHost(previous.Address)
	if !pinned || previousHost == host && normalizedPort(previous.Port) == normalizedPort(port) {
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("dial-back succeeded, but load config to remove stale pins for %s: %w", previous.Address, err)
	}
	if _, used := peerUsingEndpoint(&cfg, peerName, previousHost, previous.Port); used {
		return nil
	}
	if err := connection.UnpinHostKeys(knownHosts, previousHost, previous.Port); err != nil {
		return fmt.Errorf("dial-back succeeded, but remove stale pins for %s: %w", previous.Address, err)
	}
	return nil
}

// peerUsingEndpoint returns a peer other than excluded whose normalized
// address host and port match, treating port 0 as the default sshd port. A
// host that does not normalize never matches: it can share no pin.
func peerUsingEndpoint(cfg *config.Config, excluded, host string, port int) (string, bool) {
	wanted, err := config.NormalizeHost(host)
	if err != nil {
		return "", false
	}
	for name, peer := range cfg.Peers {
		if name == excluded || peer.Address == "" {
			continue
		}
		if stored, ok := pinnedHost(peer.Address); ok && stored == wanted && normalizedPort(peer.Port) == normalizedPort(port) {
			return name, true
		}
	}
	return "", false
}

// pinnedHost returns the known_hosts host of a stored address. ok is false
// when that host is not a plain hostname or IP literal (an ssh_config alias
// such as "my_box"): l2sync never pins under such a host.
func pinnedHost(address string) (string, bool) {
	host, err := config.NormalizeHost(config.AddressHost(address))
	return host, err == nil
}

func normalizedPort(port int) int {
	if port == 0 {
		return config.DefaultSSHPort
	}
	return port
}

func returnHost(route transport.ReturnRoute, sshConnection string) (string, error) {
	if route.Host != "" {
		return route.Host, nil
	}
	fields := strings.Fields(sshConnection)
	if len(fields) == 0 {
		return "", fmt.Errorf("%s is not set; cannot observe the caller's address", sshConnectionEnv)
	}
	return fields[0], nil
}

// restorePeerRoute puts back the address this run replaced, unless another
// writer changed it since.
func restorePeerRoute(peerName string, previous config.Peer, address string, port int) error {
	return updateConfigLocked(func(current *config.Config) error {
		peer, exists := current.Peers[peerName]
		if !exists || peer.Address != address || peer.Port != port {
			return nil
		}
		peer.Address, peer.Port = previous.Address, previous.Port
		current.Peers[peerName] = peer
		return nil
	})
}
