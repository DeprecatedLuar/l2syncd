//go:build linux

package config

import (
	"fmt"
	"strings"
)

const (
	hostTrailingDot   = "."
	hostLeadingOption = "-"
	// hostPunctuation adds IPv6 ':' and the IPv6 zone separator '%' to the
	// hostname characters '.' and '-'.
	hostPunctuation = ".-:%"
	addressUserSep  = "@"
)

// NormalizeHost returns host lowercased and without a single trailing dot,
// the form OpenSSH matches known_hosts entries against. Only hostname and IP
// literal characters are accepted, so the result can never be read as a
// known_hosts pattern, negation, hashed entry, marker, or ssh option.
func NormalizeHost(host string) (string, error) {
	normalized := strings.TrimSuffix(strings.ToLower(host), hostTrailingDot)
	if normalized == "" {
		return "", fmt.Errorf("host %q is empty", host)
	}
	if strings.HasPrefix(normalized, hostLeadingOption) {
		return "", fmt.Errorf("host %q must not begin with %q", host, hostLeadingOption)
	}
	for _, character := range normalized {
		if !hostCharacter(character) {
			return "", fmt.Errorf("host %q contains %q; only letters, digits and %q are allowed", host, character, hostPunctuation)
		}
	}
	return normalized, nil
}

func hostCharacter(character rune) bool {
	return character >= 'a' && character <= 'z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune(hostPunctuation, character)
}

// SplitAddress splits a "user@host" or "host" destination. A user part, when
// present, must be non-empty; the host goes through NormalizeHost.
func SplitAddress(address string) (user, host string, err error) {
	user, rawHost, found := strings.Cut(address, addressUserSep)
	if !found {
		user, rawHost = "", address
	} else if user == "" {
		return "", "", fmt.Errorf("address %q has an empty user before %q", address, addressUserSep)
	}
	if rawHost == "" {
		return "", "", fmt.Errorf("address %q has an empty host", address)
	}
	host, err = NormalizeHost(rawHost)
	if err != nil {
		return "", "", fmt.Errorf("address %q: %w", address, err)
	}
	return user, host, nil
}
