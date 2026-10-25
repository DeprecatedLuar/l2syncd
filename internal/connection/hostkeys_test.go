//go:build linux

package connection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOa5yPFeboA77SXJofjIFkkOV0eAl3rSsKLIIyNMZ9jJ"

func writeSSHD(t *testing.T, dir, sshdConfig string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(sshdConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte(testHostKey+" root@host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSSHDPortRules(t *testing.T) {
	cases := []struct {
		name, sshdConfig string
		defaultPort      int
		want             int
	}{
		{"explicit", "Port 2200\n", 22, 2200},
		{"first wins", "Port 2200\nPort 2300\n", 22, 2200},
		{"default system", "PasswordAuthentication no\n", 22, 22},
		{"default termux", "", 8022, 8022},
		{"match block ignored", "Match User x\n  Port 9999\n", 22, 22},
		{"comment ignored", "# Port 9999\n", 22, 22},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeSSHD(t, dir, tc.sshdConfig)
			got, err := ReadSSHD(dir, tc.defaultPort)
			if err != nil {
				t.Fatal(err)
			}
			if got.Port != tc.want || len(got.HostKeys) != 1 || got.HostKeys[0] != testHostKey {
				t.Fatalf("ReadSSHD = %+v, want port %d and one normalized key", got, tc.want)
			}
		})
	}
}

func TestReadSSHDFollowsInclude(t *testing.T) {
	dir := t.TempDir()
	writeSSHD(t, dir, "Include sshd_config.d/*.conf\n")
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config.d", "port.conf"), []byte("Port 2022\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSSHD(dir, 22)
	if err != nil || got.Port != 2022 {
		t.Fatalf("ReadSSHD = %+v, %v, want 2022", got, err)
	}
}

func TestReadSSHDRequiresHostKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSSHD(dir, 22); err == nil {
		t.Fatal("ReadSSHD accepted a directory without host keys")
	}
}

func TestPinHostKeysReplacesAndUnpins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "known_hosts")
	if err := PinHostKeys(path, "100.64.0.5", 8022, []string{testHostKey}); err != nil {
		t.Fatal(err)
	}
	if err := PinHostKeys(path, "100.64.0.6", 22, []string{testHostKey}); err != nil {
		t.Fatal(err)
	}
	if err := PinHostKeys(path, "100.64.0.5", 8022, []string{testHostKey}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), "[100.64.0.5]:8022 ") != 1 || !strings.Contains(string(contents), "100.64.0.6 "+testHostKey+"\n") {
		t.Fatalf("known_hosts = %q", contents)
	}
	if err := UnpinHostKeys(path, "100.64.0.5", 8022); err != nil {
		t.Fatal(err)
	}
	if keys, _ := HostKeysFor(path, "100.64.0.5", 8022); len(keys) != 0 {
		t.Fatalf("unpinned host still has keys %v", keys)
	}
	if keys, _ := HostKeysFor(path, "100.64.0.6", 22); len(keys) != 1 {
		t.Fatal("unpin removed another host")
	}
}

func TestKnownHostsPatternBracketsNonDefaultPorts(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
		want string
	}{
		{"10.0.0.1", 0, "10.0.0.1"},
		{"10.0.0.1", 22, "10.0.0.1"},
		{"10.0.0.1", 8022, "[10.0.0.1]:8022"},
		{"fd7a::1", 8022, "[fd7a::1]:8022"},
	} {
		if got := KnownHostsPattern(tc.host, tc.port); got != tc.want {
			t.Fatalf("KnownHostsPattern(%q, %d) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}
