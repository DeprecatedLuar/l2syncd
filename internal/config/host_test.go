//go:build linux

package config

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		host, want string
		valid      bool
	}{
		{"relay.lan", "relay.lan", true},
		{"RELAY.Lan", "relay.lan", true},
		{"relay.lan.", "relay.lan", true},
		{"100.73.155.103", "100.73.155.103", true},
		{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0::1", true},
		{"FE80::1%ETH0", "fe80::1%eth0", true},
		{"my-host", "my-host", true},
		{"", "", false},
		{".", "", false},
		{"*", "", false},
		{"?", "", false},
		{"!x", "", false},
		{"*.example.com", "", false},
		{"host?", "", false},
		{"|x", "", false},
		{"|1|c2FsdA==|aGFzaA==", "", false},
		{"@x", "", false},
		{"@cert-authority", "", false},
		{"-oProxyCommand=x", "", false},
		{"[host]:2222", "", false},
		{"a,b", "", false},
		{"a b", "", false},
		{"a\tb", "", false},
		{"a#b", "", false},
		{"user@host", "", false},
		{"my_alias", "", false},
	}
	for _, tc := range cases {
		got, err := NormalizeHost(tc.host)
		if tc.valid {
			if err != nil || got != tc.want {
				t.Errorf("NormalizeHost(%q) = %q, %v; want %q", tc.host, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want error", tc.host, got)
		}
	}
}

func TestSplitAddress(t *testing.T) {
	cases := []struct {
		address, user, host string
		valid               bool
	}{
		{"alex@Relay.lan", "alex", "relay.lan", true},
		{"relay", "", "relay", true},
		{"alex@fe80::1%eth0", "alex", "fe80::1%eth0", true},
		{"@host", "", "", false},
		{"user@", "", "", false},
		{"", "", "", false},
		{"user@*", "", "", false},
		{"user@a@b", "", "", false},
		{"user@host name", "", "", false},
	}
	for _, tc := range cases {
		user, host, err := SplitAddress(tc.address)
		if tc.valid {
			if err != nil || user != tc.user || host != tc.host {
				t.Errorf("SplitAddress(%q) = %q, %q, %v; want %q, %q", tc.address, user, host, err, tc.user, tc.host)
			}
			continue
		}
		if err == nil {
			t.Errorf("SplitAddress(%q) = %q, %q, want error", tc.address, user, host)
		}
	}
}
