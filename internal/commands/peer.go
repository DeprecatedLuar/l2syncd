//go:build linux

package commands

import (
	"context"
	"errors"
	"fmt"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

func peerEndpoint(ctx context.Context, cfg config.Config, name string) (transport.Endpoint, error) {
	peer, exists := cfg.Peers[name]
	if !exists {
		return transport.Endpoint{}, fmt.Errorf("peer %q not found", name)
	}
	if peer.Status == config.PeerPending {
		endpoint, err := endpointForPeer(name, peer, func(publicKey string) error {
			if peer.PublicKey != "" {
				normalized, normalizeErr := connection.NormalizePublicKey(peer.PublicKey)
				if normalizeErr != nil || normalized != publicKey {
					return fmt.Errorf("peer %q public key differs from pending key", name)
				}
			}
			if err := rejectDuplicatePeerKey(cfg, name, publicKey); err != nil {
				return err
			}
			peer.PublicKey = publicKey
			peer.Status = config.PeerActive
			cfg.Peers[name] = peer
			return storePeerLocked(name, peer)
		})
		if err != nil {
			return transport.Endpoint{}, err
		}
		if err := connectionExchange(ctx, endpoint); err != nil {
			return transport.Endpoint{}, fmt.Errorf("complete pending peer %q handshake: %w", name, err)
		}
		endpoint.PublicKey = peer.PublicKey
		endpoint.AcceptPublicKey = nil
		return endpoint, nil
	}
	if peer.Status != config.PeerActive || peer.PublicKey == "" {
		return transport.Endpoint{}, fmt.Errorf("peer %q has incomplete credentials", name)
	}
	return endpointForPeer(name, peer, nil)
}

func endpointForPeer(name string, peer config.Peer, accept func(string) error) (transport.Endpoint, error) {
	address, err := config.ResolvePeerAddress(peer.Address)
	if err != nil {
		return transport.Endpoint{}, fmt.Errorf("resolve peer %q: %w", name, err)
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
		Name: name, Address: address, PublicKey: peer.PublicKey,
		LocalPublicKey: localKey, PrivateKey: paths.PrivateKey,
		AuthorizedKeys: paths.AuthorizedKeys, AcceptPublicKey: accept,
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
