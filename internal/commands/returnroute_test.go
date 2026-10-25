//go:build linux

package commands

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/transport"
)

const testReturnHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOa5yPFeboA77SXJofjIFkkOV0eAl3rSsKLIIyNMZ9jJ"

const testOtherHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHYJrMJMt84bsXDc9l4/+B1A86qQD/1v71QRyI0JFERS"

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

func addOtherPeer(t *testing.T, peer config.Peer) {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Peers["tablet"] = peer
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReturnRefusesHostPortUsedByAnotherPeer(t *testing.T) {
	cases := []struct {
		name      string
		other     config.Peer
		port      int
		pinPort   int
		pinHost   string
		routeHost string
	}{
		{"same port", config.Peer{Address: "x@100.64.0.5", Port: 8022, PublicKey: testOtherHostKey}, 8022, 8022, "100.64.0.5", ""},
		{"default port normalized", config.Peer{Address: "x@100.64.0.5", PublicKey: testOtherHostKey}, config.DefaultSSHPort, 0, "100.64.0.5", ""},
		{"override host", config.Peer{Address: "me.example", PublicKey: testOtherHostKey}, config.DefaultSSHPort, 0, "me.example", "me.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fingerprint, route := returnRouteFixture(t)
			route.Port, route.Host = tc.port, tc.routeHost
			route.HostKeys = []string{testOtherHostKey}
			addOtherPeer(t, tc.other)
			paths, err := connection.DefaultPaths()
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.PinHostKeys(paths.KnownHosts, tc.pinHost, tc.pinPort, []string{testReturnHostKey}); err != nil {
				t.Fatal(err)
			}
			before, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			pinsBefore, err := connection.HostKeysFor(paths.KnownHosts, tc.pinHost, tc.pinPort)
			if err != nil {
				t.Fatal(err)
			}
			dialed := stubReturnDial(t, nil)
			err = verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection)
			if err == nil || !strings.Contains(err.Error(), `"tablet"`) {
				t.Fatalf("err = %v, want refusal naming tablet", err)
			}
			if dialed.Address != "" {
				t.Fatalf("dial attempted: %+v", *dialed)
			}
			after, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			if after.Peers["phone"] != before.Peers["phone"] || after.Peers["tablet"] != before.Peers["tablet"] {
				t.Fatalf("config changed: %+v", after.Peers)
			}
			pinsAfter, err := connection.HostKeysFor(paths.KnownHosts, tc.pinHost, tc.pinPort)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pinsBefore, pinsAfter) {
				t.Fatalf("pins changed: %v -> %v", pinsBefore, pinsAfter)
			}
		})
	}
}

func TestVerifyReturnStalePinRemoval(t *testing.T) {
	const staleHost, stalePort = "old.example", 2222
	cases := []struct {
		name       string
		sharedWith *config.Peer
		wantPinned bool
	}{
		{"unshared pins removed", nil, false},
		{"shared pins kept", &config.Peer{Address: "x@old.example", Port: stalePort, PublicKey: testOtherHostKey}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fingerprint, route := returnRouteFixture(t)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Peers["phone"] = config.Peer{Address: "u0_a1@" + staleHost, Port: stalePort, PublicKey: cfg.Peers["phone"].PublicKey}
			if tc.sharedWith != nil {
				cfg.Peers["tablet"] = *tc.sharedWith
			}
			if err := config.Save(cfg); err != nil {
				t.Fatal(err)
			}
			paths, err := connection.DefaultPaths()
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.PinHostKeys(paths.KnownHosts, staleHost, stalePort, []string{testReturnHostKey}); err != nil {
				t.Fatal(err)
			}
			stubReturnDial(t, nil)
			if err := verifyReturnRoute(context.Background(), "phone", fingerprint, route, testSSHConnection); err != nil {
				t.Fatal(err)
			}
			keys, err := connection.HostKeysFor(paths.KnownHosts, staleHost, stalePort)
			if err != nil {
				t.Fatal(err)
			}
			if (len(keys) > 0) != tc.wantPinned {
				t.Fatalf("stale pins = %v, wantPinned %v", keys, tc.wantPinned)
			}
		})
	}
}
