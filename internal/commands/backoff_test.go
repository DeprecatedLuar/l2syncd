//go:build linux

package commands

import (
	"testing"
	"time"
)

func TestPeerBackoffDoublesCapsAndResets(t *testing.T) {
	backoff := newPeerBackoff()
	backoff.jitter = func(time.Duration) time.Duration { return 0 }
	now := time.Unix(0, 0)
	if !backoff.Ready("phone", now) {
		t.Fatal("unknown peer not ready")
	}
	backoff.Fail("phone", now)
	if backoff.Ready("phone", now.Add(peerBackoffStart-time.Second)) {
		t.Fatal("peer ready before its backoff elapsed")
	}
	if !backoff.Ready("phone", now.Add(peerBackoffStart)) {
		t.Fatal("peer not ready after its backoff elapsed")
	}
	for range 20 {
		backoff.Fail("phone", now)
	}
	if wait, ok := backoff.Next(now); !ok || wait != peerBackoffMax {
		t.Fatalf("Next = %v, %v, want %v", wait, ok, peerBackoffMax)
	}
	backoff.Reset("phone")
	if _, ok := backoff.Next(now); ok {
		t.Fatal("Next reports a wait after Reset")
	}
}

func TestPeerBackoffNextIsEarliestPeer(t *testing.T) {
	backoff := newPeerBackoff()
	backoff.jitter = func(time.Duration) time.Duration { return 0 }
	now := time.Unix(0, 0)
	backoff.Fail("slow", now)
	backoff.Fail("slow", now)
	backoff.Fail("fast", now)
	if wait, ok := backoff.Next(now); !ok || wait != peerBackoffStart {
		t.Fatalf("Next = %v, %v, want %v", wait, ok, peerBackoffStart)
	}
}

func TestPeerBackoffJitterStaysWithinBound(t *testing.T) {
	backoff := newPeerBackoff()
	now := time.Unix(0, 0)
	backoff.Fail("phone", now)
	wait, _ := backoff.Next(now)
	if wait < peerBackoffStart || wait > peerBackoffStart+peerBackoffStart/peerBackoffJitterRatio {
		t.Fatalf("jittered wait %v outside [%v, +20%%]", wait, peerBackoffStart)
	}
}

func TestPeerBackoffNextIgnoresExpiredEntries(t *testing.T) {
	backoff := newPeerBackoff()
	backoff.jitter = func(time.Duration) time.Duration { return 0 }
	now := time.Unix(0, 0)
	backoff.Fail("gone", now.Add(-time.Hour))
	if wait, ok := backoff.Next(now); ok {
		t.Fatalf("Next = %v, %v for an expired entry, want none", wait, ok)
	}
	if !backoff.Ready("gone", now) {
		t.Fatal("expired peer not ready")
	}
	backoff.Fail("slow", now)
	backoff.Fail("slow", now)
	backoff.Fail("fast", now)
	if wait, ok := backoff.Next(now); !ok || wait != peerBackoffStart {
		t.Fatalf("Next = %v, %v, want %v", wait, ok, peerBackoffStart)
	}
}
