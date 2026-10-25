//go:build linux

package commands

import (
	"context"
	"errors"
	"slices"
	"testing"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

const testReturnHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOa5yPFeboA77SXJofjIFkkOV0eAl3rSsKLIIyNMZ9jJ"

const testSSHConnection = "100.64.0.5 50000 100.64.0.1 22"

func returnRouteFixture(t *testing.T) (string, transport.ReturnRoute) {
	t.Helper()
	_, cfg := cycleTestConfig(t, true)
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := connection.Fingerprint(cfg.Peers["phone"].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint, transport.ReturnRoute{User: "u0_a1", Port: 8022, HostKeys: []string{testReturnHostKey}}
}

func stubReturnDial(t *testing.T, result error) *transport.Endpoint {
	t.Helper()
	dialed := &transport.Endpoint{}
	previous := returnDial
	returnDial = func(_ context.Context, endpoint transport.Endpoint) error {
		*dialed = endpoint
		return result
	}
	t.Cleanup(func() { returnDial = previous })
	return dialed
}

func TestVerifyReturnStoresDerivedAddressAndPins(t *testing.T) {
	fingerprint, route := returnRouteFixture(t)
	dialed := stubReturnDial(t, nil)
	if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Peers["phone"]; got.Address != "u0_a1@100.64.0.5" || got.Port != 8022 {
		t.Fatalf("peer = %+v", got)
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if keys, _ := connection.HostKeysFor(paths.KnownHosts, "100.64.0.5", 8022); len(keys) != 1 {
		t.Fatalf("pinned keys = %v", keys)
	}
	if dialed.Address != "u0_a1@100.64.0.5" || dialed.Port != 8022 || !slices.Contains(dialed.KnownHosts, paths.KnownHosts) {
		t.Fatalf("dialed endpoint = %+v", *dialed)
	}
}

func TestVerifyReturnDefaultPortDialsWithPortZero(t *testing.T) {
	fingerprint, route := returnRouteFixture(t)
	route.Port = config.DefaultSSHPort
	dialed := stubReturnDial(t, nil)
	if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection); err != nil {
		t.Fatal(err)
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if dialed.Address != "u0_a1@100.64.0.5" || dialed.Port != 0 {
		t.Fatalf("dialed endpoint = %+v", *dialed)
	}
	if keys, _ := connection.HostKeysFor(paths.KnownHosts, "100.64.0.5", 0); len(keys) != 1 {
		t.Fatalf("pinned keys = %v", keys)
	}
}

func TestVerifyReturnRevertsAddressAndPinsOnDialFailure(t *testing.T) {
	fingerprint, route := returnRouteFixture(t)
	before, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	stubReturnDial(t, errors.New("connect timeout"))
	if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection); err == nil {
		t.Fatal("verifyReturnRoute succeeded despite dial failure")
	}
	after, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Peers["phone"] != before.Peers["phone"] {
		t.Fatalf("peer not restored: %+v, want %+v", after.Peers["phone"], before.Peers["phone"])
	}
	paths, err := connection.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if keys, _ := connection.HostKeysFor(paths.KnownHosts, "100.64.0.5", 8022); len(keys) != 0 {
		t.Fatalf("pins left after failure: %v", keys)
	}
}

func TestVerifyReturnHonorsHostOverride(t *testing.T) {
	fingerprint, route := returnRouteFixture(t)
	stubReturnDial(t, nil)
	route.Host = "me.example"
	if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Peers["phone"].Address; got != "u0_a1@me.example" {
		t.Fatalf("address = %q", got)
	}
}

func TestVerifyReturnRejectsMissingSSHConnection(t *testing.T) {
	fingerprint, route := returnRouteFixture(t)
	if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, ""); err == nil {
		t.Fatal("accepted a route with no observable source address")
	}
}
