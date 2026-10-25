//go:build linux

package connection

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"l2syncd/internal/config"
)

const (
	systemSSHDir      = "/etc/ssh"
	termuxSSHDir      = "/data/data/com.termux/files/usr/etc/ssh"
	termuxDefaultPort = 8022
	sshdConfigName    = "sshd_config"
	hostKeyGlob       = "ssh_host_*_key.pub"
	knownHostsMode    = 0o600
	sshdIncludeDepth  = 8
	maxTCPPort        = 65535
)

// SSHD describes how this machine's sshd is reached: its listen port and its
// public host keys.
type SSHD struct {
	Port     int
	HostKeys []string
}

// LocalSSHD reads this machine's sshd configuration, preferring Termux's
// prefix when present. sshd -T is unusable here: it requires root.
func LocalSSHD() (SSHD, error) {
	for _, candidate := range []struct {
		dir  string
		port int
	}{{termuxSSHDir, termuxDefaultPort}, {systemSSHDir, config.DefaultSSHPort}} {
		if _, err := os.Stat(filepath.Join(candidate.dir, sshdConfigName)); err == nil {
			return ReadSSHD(candidate.dir, candidate.port)
		}
	}
	return SSHD{}, errors.New("no sshd_config found; this machine must run sshd to be reachable")
}

// ReadSSHD returns the first Port in dir's sshd_config (following Include,
// stopping at the first Match block), or defaultPort, plus dir's host keys.
func ReadSSHD(dir string, defaultPort int) (SSHD, error) {
	port, err := sshdPort(filepath.Join(dir, sshdConfigName), dir, sshdIncludeDepth)
	if err != nil {
		return SSHD{}, err
	}
	if port == 0 {
		port = defaultPort
	}
	paths, err := filepath.Glob(filepath.Join(dir, hostKeyGlob))
	if err != nil {
		return SSHD{}, err
	}
	keys := make([]string, 0, len(paths))
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			return SSHD{}, fmt.Errorf("read host key %q: %w", path, err)
		}
		key, err := NormalizeHostKey(string(contents))
		if err != nil {
			return SSHD{}, fmt.Errorf("host key %q: %w", path, err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return SSHD{}, fmt.Errorf("no sshd host keys in %q", dir)
	}
	return SSHD{Port: port, HostKeys: keys}, nil
}

func sshdPort(path, base string, depth int) (int, error) {
	if depth == 0 {
		return 0, fmt.Errorf("sshd Include nesting too deep at %q", path)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %q: %w", path, err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "match":
			return 0, nil
		case "port":
			port, err := strconv.Atoi(fields[1])
			if err != nil || port < 1 || port > maxTCPPort {
				return 0, fmt.Errorf("invalid Port %q in %q", fields[1], path)
			}
			return port, nil
		case "include":
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(base, pattern)
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					return 0, fmt.Errorf("Include %q in %q: %w", pattern, path, err)
				}
				for _, match := range matches {
					port, err := sshdPort(match, base, depth-1)
					if err != nil || port != 0 {
						return port, err
					}
				}
			}
		}
	}
	return 0, scanner.Err()
}

// NormalizeHostKey returns "<type> <base64>" without a comment.
func NormalizeHostKey(value string) (string, error) {
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return "", errors.New(`host key must be "<type> <base64>"`)
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", fmt.Errorf("host key body: %w", err)
	}
	return fields[0] + " " + fields[1], nil
}

// KnownHostsPattern is the known_hosts host field OpenSSH looks up.
func KnownHostsPattern(host string, port int) string {
	if port == 0 || port == config.DefaultSSHPort {
		return host
	}
	return "[" + host + "]:" + strconv.Itoa(port)
}

// HostKeysFor returns the keys pinned for host:port.
func HostKeysFor(path, host string, port int) ([]string, error) {
	lines, err := readKnownHosts(path)
	if err != nil {
		return nil, err
	}
	pattern := KnownHostsPattern(host, port)
	var keys []string
	for _, line := range lines {
		if field, key, found := strings.Cut(line, " "); found && field == pattern {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// PinHostKeys makes keys the only keys pinned for host:port.
func PinHostKeys(path, host string, port int, keys []string) error {
	if host == "" || strings.ContainsAny(host, " \t[],#") {
		return fmt.Errorf("invalid known_hosts host %q", host)
	}
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		value, err := NormalizeHostKey(key)
		if err != nil {
			return err
		}
		normalized = append(normalized, value)
	}
	return rewriteKnownHosts(path, KnownHostsPattern(host, port), normalized)
}

// UnpinHostKeys removes every key pinned for host:port.
func UnpinHostKeys(path, host string, port int) error {
	return rewriteKnownHosts(path, KnownHostsPattern(host, port), nil)
}

func rewriteKnownHosts(path, pattern string, keys []string) error {
	return withAuthorizedLock(path, func() error {
		lines, err := readKnownHosts(path)
		if err != nil {
			return err
		}
		var updated bytes.Buffer
		for _, line := range lines {
			if field, _, _ := strings.Cut(line, " "); field != pattern {
				updated.WriteString(line + "\n")
			}
		}
		for _, key := range keys {
			updated.WriteString(pattern + " " + key + "\n")
		}
		return replaceFile(path, updated.Bytes(), knownHostsMode)
	})
}

func readKnownHosts(path string) ([]string, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}
	var lines []string
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}
