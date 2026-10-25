//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"
	"os/user"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

var (
	connectionVerifyReturn = transport.VerifyReturn
	localSSHD              = connection.LocalSSHD
)

func peerEndpoint(ctx context.Context, cfg config.Config, name string) (transport.Endpoint, error) {
	peer, exists := cfg.Peers[name]
	if !exists {
		return transport.Endpoint{}, fmt.Errorf("peer %q not found", name)
	}
	if peer.PublicKey != "" {
		return endpointForPeer(name, peer, nil)
	}
	return activatePeer(ctx, cfg, name, "")
}

// activatePeer completes first contact with a pending peer: the hello pins
// its key and installs its reciprocal grant, then the peer must dial back
// over the returned route. Any failure returns this side to pending.
func activatePeer(ctx context.Context, cfg config.Config, name, returnAddress string) (transport.Endpoint, error) {
	peer := cfg.Peers[name]
	endpoint, err := endpointForPeer(name, peer, func(publicKey string) error {
		if err := rejectDuplicatePeerKey(cfg, name, publicKey); err != nil {
			return err
		}
		peer.PublicKey = publicKey
		cfg.Peers[name] = peer
		return storePeerLocked(name, peer)
	})
	if err != nil {
		return transport.Endpoint{}, err
	}
	if err := connectionExchange(ctx, endpoint); err != nil {
		if peer.PublicKey != "" {
			err = errors.Join(err, deactivatePeer(name, peer.PublicKey))
		}
		return transport.Endpoint{}, fmt.Errorf("complete first contact with peer %q: %w", name, err)
	}
	endpoint.PublicKey = peer.PublicKey
	endpoint.AcceptPublicKey = nil
	route, err := localReturnRoute(returnAddress)
	if err == nil {
		err = connectionVerifyReturn(ctx, endpoint, route)
	}
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("peer %q cannot reach this machine back: %w; if the address it sees is wrong, rerun: l2sync connection add %s --address <user@host>", name, errors.Join(err, deactivatePeer(name, peer.PublicKey)), name)
	}
	return endpoint, nil
}

// deactivatePeer returns name to pending and removes its reciprocal grant.
func deactivatePeer(name, publicKey string) error {
	paths, err := connection.DefaultPaths()
	if err != nil {
		return err
	}
	configErr := updateConfigLocked(func(current *config.Config) error {
		peer, exists := current.Peers[name]
		if !exists || peer.PublicKey != publicKey {
			return nil
		}
		peer.PublicKey = ""
		current.Peers[name] = peer
		return nil
	})
	return errors.Join(configErr, connection.RemoveGrant(paths.AuthorizedKeys, name, publicKey))
}

// localReturnRoute describes how a peer reaches this machine. returnAddress
// ("user@host" or "host") overrides the user and the host the peer observes.
func localReturnRoute(returnAddress string) (transport.ReturnRoute, error) {
	sshd, err := localSSHD()
	if err != nil {
		return transport.ReturnRoute{}, err
	}
	current, err := user.Current()
	if err != nil {
		return transport.ReturnRoute{}, fmt.Errorf("current user: %w", err)
	}
	route := transport.ReturnRoute{User: current.Username, Port: sshd.Port, HostKeys: sshd.HostKeys}
	if returnAddress != "" {
		userPart, host, err := parseReturnAddress(returnAddress)
		if err != nil {
			return transport.ReturnRoute{}, err
		}
		if userPart != "" {
			route.User = userPart
		}
		route.Host = host
	}
	return route, nil
}

// parseReturnAddress validates an --address value, "user@host" or "host",
// and returns its user (empty when absent) and normalized host.
func parseReturnAddress(value string) (user, host string, err error) {
	if err := config.ValidatePeerAddress(value); err != nil {
		return "", "", fmt.Errorf("--address: %w", err)
	}
	user, host, err = config.SplitAddress(value)
	if err != nil {
		return "", "", fmt.Errorf("--address: %w", err)
	}
	return user, host, nil
}

func endpointForPeer(name string, peer config.Peer, accept func(string) error) (transport.Endpoint, error) {
	if peer.Address == "" {
		return transport.Endpoint{}, fmt.Errorf("peer %q has no address yet; it is learned when %q next connects to this machine", name, name)
	}
	if err := config.ValidatePeerAddress(peer.Address); err != nil {
		return transport.Endpoint{}, fmt.Errorf("peer %q address: %w", name, err)
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		return transport.Endpoint{}, err
	}
	localKey, err := connection.EnsureKey(paths)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("load installation key: %w", err)
	}
	return transport.Endpoint{
		Name: name, Address: peer.Address, Port: peer.Port, PublicKey: peer.PublicKey,
		LocalPublicKey: localKey, PrivateKey: paths.PrivateKey,
		AuthorizedKeys: paths.AuthorizedKeys, AcceptPublicKey: accept,
		KnownHosts: []string{paths.KnownHosts, paths.UserKnownHosts},
	}, nil
}

func peerFingerprint(peer config.Peer) (string, error) {
	if peer.PublicKey == "" {
		return "", errors.New("peer public key is unavailable")
	}
	return connection.Fingerprint(peer.PublicKey)
}

func localFingerprint() (string, error) {
	paths, err := connection.DefaultPaths()
	if err != nil {
		return "", err
	}
	key, err := connection.EnsureKey(paths)
	if err != nil {
		return "", err
	}
	return connection.Fingerprint(key)
}
