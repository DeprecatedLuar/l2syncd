//go:build linux

package commands

import (
	"math/rand/v2"
	"time"
)

const (
	peerBackoffStart       = 10 * time.Second
	peerBackoffMax         = 5 * time.Minute
	peerBackoffJitterRatio = 5 // jitter adds up to delay/5
)

// peerBackoff tracks retry delay per peer, so one unreachable peer never
// delays folders bound to another.
type peerBackoff struct {
	delay  map[string]time.Duration
	until  map[string]time.Time
	jitter func(time.Duration) time.Duration
}

func newPeerBackoff() *peerBackoff {
	return &peerBackoff{
		delay: make(map[string]time.Duration),
		until: make(map[string]time.Time),
		jitter: func(delay time.Duration) time.Duration {
			return rand.N(delay/peerBackoffJitterRatio + 1)
		},
	}
}

func (backoff *peerBackoff) Ready(peer string, now time.Time) bool {
	return !now.Before(backoff.until[peer])
}

func (backoff *peerBackoff) Fail(peer string, now time.Time) {
	delay := backoff.delay[peer]
	switch {
	case delay == 0:
		delay = peerBackoffStart
	case delay < peerBackoffMax:
		delay = min(delay*2, peerBackoffMax)
	}
	backoff.delay[peer] = delay
	backoff.until[peer] = now.Add(delay + backoff.jitter(delay))
}

func (backoff *peerBackoff) Reset(peer string) {
	delete(backoff.delay, peer)
	delete(backoff.until, peer)
}

// Next returns the wait until the earliest still-backed-off peer is ready
// again; expired entries have nothing to wait for.
func (backoff *peerBackoff) Next(now time.Time) (time.Duration, bool) {
	var earliest time.Time
	for _, until := range backoff.until {
		if !until.After(now) {
			continue
		}
		if earliest.IsZero() || until.Before(earliest) {
			earliest = until
		}
	}
	if earliest.IsZero() {
		return 0, false
	}
	return earliest.Sub(now), true
}
