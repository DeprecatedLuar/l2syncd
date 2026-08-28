//go:build linux

package commands

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"golang.org/x/term"

	"l2syncd/internal/androidexec"
	"l2syncd/internal/config"
	connectionpkg "l2syncd/internal/connection"
	"l2syncd/internal/guard"
	"l2syncd/internal/lock"
	"l2syncd/internal/peername"
	"l2syncd/internal/transport"
)

const (
	connectionExitOK    = 0
	connectionExitError = 1
	connectionSSH       = "ssh"
	connectionBinary    = "l2sync"
)

const (
	connectionStatusPending   = "~"
	connectionStatusHealthy   = "+"
	connectionStatusRevoked   = "x"
	connectionStatusUnhealthy = "-"

	ansiDim   = "\x1b[2m"
	ansiBlue  = "\x1b[38;2;138;180;248m"
	ansiReset = "\x1b[0m"
)

// connectionStatusRank orders connection ls rows: pending first, then
// healthy, then revoked, then unhealthy.
var connectionStatusRank = map[string]int{
	connectionStatusPending:   0,
	connectionStatusHealthy:   1,
	connectionStatusRevoked:   2,
	connectionStatusUnhealthy: 3,
}

var (
	connectionProbe      = probeExistingAccess
	connectionInstall    = installRemoteGrant
	connectionExchange   = transport.Exchange
	connectionListShares = transport.ListShares
	loginShell           = currentLoginShell
)

// Connection dispatches peer credential management commands. With no
// subcommand it defaults to listing, same as "connection ls".
func Connection(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return connectionList(nil, stdout, stderr)
	}
	switch args[0] {
	case "add":
		return connectionAdd(args[1:], os.Stdin, stdout, stderr)
	case "ls", "list":
		return connectionList(args[1:], stdout, stderr)
	case "rm", "remove":
		return connectionRemove(args[1:], stderr)
	case "edit":
		return ConfigEdit(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "l2sync: unknown connection command %q\n", args[0])
		return connectionExitError
	}
}

func connectionAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	name, address, suppliedKey, err := parseConnectionAdd(args, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	if existing, found := cfg.Peers[name]; found {
		if existing.Address != address || suppliedKey != "" && existing.PublicKey != "" && existing.PublicKey != suppliedKey {
			fmt.Fprintf(stderr, "l2sync: peer %q already exists with different connection data\n", name)
			return connectionExitError
		}
		if suppliedKey == "" && existing.PublicKey != "" {
			if err := storePeerLocked(name, existing); err != nil {
				fmt.Fprintf(stderr, "l2sync: verify active peer: %v\n", err)
				return connectionExitError
			}
			return connectionExitOK
		}
	}
	if suppliedKey != "" {
		if err := rejectDuplicatePeerKey(cfg, name, suppliedKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: %v\n", err)
			return connectionExitError
		}
		paths, localKey, ok := resolveLocalKey(stderr, "load")
		if !ok {
			return connectionExitError
		}
		if localKey == suppliedKey {
			fmt.Fprintln(stderr, "l2sync: peer public key is this installation's key")
			return connectionExitError
		}
		cfg.Peers[name] = config.Peer{Address: address, PublicKey: suppliedKey}
		if err := storePeerLocked(name, cfg.Peers[name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
			return connectionExitError
		}
		if err := connectionpkg.AddGrant(paths.AuthorizedKeys, name, suppliedKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: install restricted grant: %v (peer remains pending)\n", err)
			return connectionExitError
		}
		if shell, err := loginShell(); err == nil && filepath.Base(shell) == "bash" {
			fmt.Fprintf(stderr, "l2sync: warning: login shell %q sources startup files before SSH forced commands; use a dedicated sync account for hardened isolation\n", shell)
		}
		return connectionExitOK
	}

	_, localKey, ok := resolveLocalKey(stderr, "prepare")
	if !ok {
		return connectionExitError
	}
	resolved, err := config.ResolvePeerAddress(address)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve destination: %v\n", err)
		return connectionExitError
	}
	probeErr := connectionProbe(context.Background(), resolved)
	if probeErr != nil && errors.Is(probeErr, errSSHUnreachable) {
		fmt.Fprintf(stderr, "l2sync: %s is unreachable via SSH: %v\n", resolved, probeErr)
		return connectionExitError
	}
	available := probeErr == nil
	if !available {
		cfg.Peers[name] = config.Peer{Address: address}
		if err := storePeerLocked(name, cfg.Peers[name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
			return connectionExitError
		}
		localName, localAddress, addressKnownGood := installationAddress()
		command := fmt.Sprintf("l2sync connection add %s %s --key %q", localName, localAddress, localKey)
		if isTerminalWriter(stdout) {
			command = ansiBlue + command + ansiReset
		}
		fmt.Fprintf(stdout, "%s is reachable but doesn't have your key yet. Have someone run this there:\n\n  %s\n\n", resolved, command)
		if !addressKnownGood {
			fmt.Fprintf(stdout, "warning: this machine's hostname (%q) won't resolve from another host — replace %q above with an address or hostname that actually reaches this machine.\n\n", localAddress, localAddress)
		}
		return connectionExitOK
	}
	peer := config.Peer{Address: address}
	cfg.Peers[name] = peer
	if err := storePeerLocked(name, peer); err != nil {
		fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
		return connectionExitError
	}
	localName, localAddress, _ := installationAddress()
	if err := connectionInstall(context.Background(), resolved, localName, localAddress, localKey); err != nil {
		fmt.Fprintf(stderr, "l2sync: install remote restricted grant: %v\n", err)
		return connectionExitError
	}
	endpoint, err := endpointForPeer(name, peer, func(publicKey string) error {
		if err := rejectDuplicatePeerKey(cfg, name, publicKey); err != nil {
			return err
		}
		peer.PublicKey = publicKey
		cfg.Peers[name] = peer
		return storePeerLocked(name, peer)
	})
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: prepare peer handshake: %v\n", err)
		return connectionExitError
	}
	if err := connectionExchange(context.Background(), endpoint); err != nil {
		fmt.Fprintf(stderr, "l2sync: peer handshake: %v\n", err)
		return connectionExitError
	}
	return connectionExitOK
}

// resolveLocalKey resolves this installation's key paths and ensures its
// key pair exists, writing an error to stderr and reporting failure on the
// caller's behalf. verb names the EnsureKey step in the error message
// (e.g. "load", "prepare").
func resolveLocalKey(stderr io.Writer, verb string) (connectionpkg.Paths, string, bool) {
	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve installation key: %v\n", err)
		return connectionpkg.Paths{}, "", false
	}
	localKey, err := connectionpkg.EnsureKey(paths)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %s installation key: %v\n", verb, err)
		return connectionpkg.Paths{}, "", false
	}
	return paths, localKey, true
}

func storePeerLocked(name string, peer config.Peer) error {
	return updateConfigLocked(func(current *config.Config) error {
		if err := rejectDuplicatePeerKey(*current, name, peer.PublicKey); peer.PublicKey != "" && err != nil {
			return err
		}
		if existing, exists := current.Peers[name]; exists {
			if existing.Address != peer.Address {
				return fmt.Errorf("peer %q address changed concurrently", name)
			}
			if existing.PublicKey != "" && peer.PublicKey != "" && existing.PublicKey != peer.PublicKey {
				return fmt.Errorf("peer %q public key changed concurrently", name)
			}
			if existing.PublicKey != "" && peer.PublicKey == "" {
				return fmt.Errorf("peer %q cannot lose its pinned public key", name)
			}
		}
		current.Peers[name] = peer
		return nil
	})
}

func connectionList(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: l2sync connection ls")
		return connectionExitError
	}
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}

	type row struct {
		name, symbol string
		peer         config.Peer
	}
	rows := make([]row, 0, len(cfg.Peers))
	for _, name := range sortedKeys(cfg.Peers) {
		peer := cfg.Peers[name]
		rows = append(rows, row{name: name, symbol: connectionStatusSymbol(cfg, name, peer), peer: peer})
	}
	if len(rows) == 0 {
		return connectionExitOK
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return connectionStatusRank[rows[i].symbol] < connectionStatusRank[rows[j].symbol]
	})

	var buffer bytes.Buffer
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(writer, "%s %s\t%s\n", r.symbol, r.name, r.peer.Address)
	}
	writer.Flush()

	dim := isTerminalWriter(stdout)
	for i, line := range strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n") {
		if dim && (rows[i].symbol == connectionStatusUnhealthy || rows[i].symbol == connectionStatusRevoked) {
			line = ansiDim + line + ansiReset
		}
		fmt.Fprintln(stdout, line)
	}
	return connectionExitOK
}

// isTerminalWriter reports whether writer is a terminal, so ANSI styling is
// only emitted for interactive output and not for redirected/piped output.
func isTerminalWriter(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// connectionStatusSymbol reports a peer's connection state: a peer with no
// pinned key is never probed (that could silently trigger a first-contact
// handshake mid-listing) and reported pending; a pinned peer is live-checked
// by requesting its share list — an SSH public-key rejection is reported as
// revoked (the peer very likely ran "connection rm" on us) rather than
// merely unreachable.
func connectionStatusSymbol(cfg config.Config, name string, peer config.Peer) string {
	if peer.PublicKey == "" {
		return connectionStatusPending
	}
	endpoint, err := peerEndpoint(context.Background(), cfg, name)
	if err != nil {
		return connectionStatusUnhealthy
	}
	if _, err := connectionListShares(context.Background(), endpoint); err != nil {
		if transport.IsAuthError(err) {
			return connectionStatusRevoked
		}
		return connectionStatusUnhealthy
	}
	return connectionStatusHealthy
}

// connectionRemove always revokes: it cuts the peer's restricted SSH grant
// first, then reconciles folder bookkeeping to match. A shared folder is
// ours to keep, so it is only unbound (an unbound folder is refused to
// everyone, concept.md 830-835); a remote folder existed only as that peer's
// offer, so its registration and index are dropped, mirroring leave. It
// never contacts the peer — revocation must work even when the peer is
// unreachable or hostile.
func connectionRemove(args []string, stderr io.Writer) (exitCode int) {
	name, force, err := parseConnectionRemove(args)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}

	transactionLock, err := lock.AcquireJoinWait(context.Background(), lock.DefaultWait)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: acquire folder transaction lock: %v\n", err)
		return connectionExitError
	}
	defer func() {
		if releaseErr := lock.Release(transactionLock); releaseErr != nil {
			fmt.Fprintf(stderr, "l2sync: release folder transaction lock: %v\n", releaseErr)
			if exitCode == connectionExitOK {
				exitCode = connectionExitError
			}
		}
	}()

	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	peer, exists := cfg.Peers[name]
	if !exists {
		fmt.Fprintf(stderr, "l2sync: peer %q not found\n", name)
		return connectionExitError
	}

	sharedTargets, remoteTargets := revocationTargets(cfg, name)
	if !force && (len(sharedTargets) > 0 || len(remoteTargets) > 0) {
		proceed, promptErr := promptRevocationInteractive(stderr, name, sharedTargets, remoteTargets)
		if promptErr != nil {
			fmt.Fprintf(stderr, "l2sync: %v\n", promptErr)
			return connectionExitError
		}
		if !proceed {
			fmt.Fprintln(stderr, "l2sync: revocation cancelled")
			return connectionExitError
		}
	}

	// Folder ids must be captured before the grant or config are touched:
	// once the remote registration is gone, its marker can no longer be
	// resolved from config alone.
	folderIDs := make(map[string]string, len(remoteTargets))
	for _, remoteName := range remoteTargets {
		if marker, markerErr := guard.ReadMarker(cfg.Remote[remoteName].Path); markerErr == nil {
			folderIDs[remoteName] = marker.ID
		}
	}

	if peer.PublicKey != "" {
		paths, err := connectionpkg.DefaultPaths()
		if err != nil {
			fmt.Fprintf(stderr, "l2sync: resolve authorized_keys: %v\n", err)
			return connectionExitError
		}
		if err := connectionpkg.RemoveGrant(paths.AuthorizedKeys, name, peer.PublicKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: remove restricted grant: %v; retry connection rm\n", err)
			return connectionExitError
		}
	}

	if err := updateConfigLocked(func(current *config.Config) error {
		latest, exists := current.Peers[name]
		if !exists {
			return nil
		}
		if latest.PublicKey != peer.PublicKey || latest.Address != peer.Address {
			return fmt.Errorf("peer %q changed during removal", name)
		}
		for _, sharedName := range sharedTargets {
			folder, exists := current.Shared[sharedName]
			if !exists {
				continue
			}
			if len(folder.Peers) != 1 || folder.Peers[0] != name {
				return fmt.Errorf("shared folder %q binding changed concurrently", sharedName)
			}
			folder.Peers = nil
			current.Shared[sharedName] = folder
		}
		for _, remoteName := range remoteTargets {
			folder, exists := current.Remote[remoteName]
			if !exists {
				continue
			}
			if len(folder.Peers) != 1 || folder.Peers[0] != name {
				return fmt.Errorf("remote folder %q binding changed concurrently", remoteName)
			}
			delete(current.Remote, remoteName)
		}
		delete(current.Peers, name)
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "l2sync: restricted grant removed, but update config: %v; folders left bound: %s\n", err, strings.Join(append(append([]string{}, sharedTargets...), remoteTargets...), ", "))
		return connectionExitError
	}

	for _, remoteName := range remoteTargets {
		id := folderIDs[remoteName]
		if id == "" {
			continue
		}
		if err := pruneIndex(id); err != nil {
			fmt.Fprintf(stderr, "l2sync: peer %q revoked, but prune index for folder %q: %v\n", name, remoteName, err)
			return connectionExitError
		}
	}

	return connectionExitOK
}

func parseConnectionRemove(args []string) (name string, force bool, err error) {
	const usage = "usage: l2sync connection rm <name> [--force]"
	switch len(args) {
	case 1:
		return args[0], false, nil
	case 2:
		if args[1] != "--force" {
			return "", false, errors.New(usage)
		}
		return args[0], true, nil
	default:
		return "", false, errors.New(usage)
	}
}

// promptRevocationInteractive asks for confirmation before revoking a peer
// bound to folders. It never prompts when stdin is not a terminal: concept.md
// 8.1 requires a non-interactive invocation needing a decision to be an
// error, never a silently chosen default — the caller must pass --force.
func promptRevocationInteractive(stderr io.Writer, peerName string, sharedTargets, remoteTargets []string) (bool, error) {
	info, statErr := os.Stdin.Stat()
	if statErr != nil || info.Mode()&os.ModeCharDevice == 0 {
		names := append(append([]string{}, sharedTargets...), remoteTargets...)
		return false, fmt.Errorf("peer %q is still bound to folder(s) %s; rerun interactively or pass --force to revoke anyway", peerName, strings.Join(names, ", "))
	}
	fmt.Fprintf(stderr, "%s bound to:\n", peerName)
	for _, sharedName := range sharedTargets {
		fmt.Fprintf(stderr, "  %s\n", sharedName)
	}
	for _, remoteName := range remoteTargets {
		fmt.Fprintf(stderr, "  %s\n", remoteName)
	}
	fmt.Fprint(stderr, "revoke? [y/N]: ")
	line, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if readErr != nil && answer == "" {
		return false, nil
	}
	return answer == "y" || answer == "yes", nil
}

// revocationTargets reports the folders that will be affected by revoking
// peerName, split by table: at most one shared folder and one remote folder
// can bind a single peer (preflight.Validate enforces exactly-one/at-most-one
// peer per folder), but both collections are returned in full for a stable,
// readable confirmation listing.
func revocationTargets(cfg config.Config, peerName string) (sharedTargets, remoteTargets []string) {
	for name, folder := range cfg.Shared {
		if len(folder.Peers) == 1 && folder.Peers[0] == peerName {
			sharedTargets = append(sharedTargets, name)
		}
	}
	for name, folder := range cfg.Remote {
		if len(folder.Peers) == 1 && folder.Peers[0] == peerName {
			remoteTargets = append(remoteTargets, name)
		}
	}
	sort.Strings(sharedTargets)
	sort.Strings(remoteTargets)
	return sharedTargets, remoteTargets
}

func parseConnectionAdd(args []string, stdin io.Reader) (string, string, string, error) {
	if len(args) < 1 {
		return "", "", "", errors.New("usage: l2sync connection add <name> [destination] [--key <pubkey>]")
	}
	name := strings.ToLower(args[0])
	if err := peername.Validate(name); err != nil {
		return "", "", "", err
	}
	address := name
	var key string
	position := 1
	if position < len(args) && args[position] != "--key" {
		address = args[position]
		position++
	}
	if position < len(args) {
		if args[position] != "--key" || position+2 != len(args) {
			return "", "", "", errors.New("usage: l2sync connection add <name> [destination] [--key <pubkey>]")
		}
		key = args[position+1]
		if key == "-" {
			contents, err := io.ReadAll(io.LimitReader(stdin, 16<<10))
			if err != nil {
				return "", "", "", fmt.Errorf("read public key: %w", err)
			}
			key = string(contents)
		}
		normalized, err := connectionpkg.NormalizePublicKey(key)
		if err != nil {
			return "", "", "", err
		}
		key = normalized
	}
	if err := config.ValidatePeerAddress(address); err != nil {
		return "", "", "", fmt.Errorf("invalid SSH destination: %w", err)
	}
	return name, address, key, nil
}

func loadConfigWithoutFolderPreflight() (config.Config, error) {
	cfg, err := config.Load()
	if errors.Is(err, config.ErrNotFound) {
		return config.New(), nil
	}
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func rejectDuplicatePeerKey(cfg config.Config, name, publicKey string) error {
	normalized, err := connectionpkg.NormalizePublicKey(publicKey)
	if err != nil {
		return err
	}
	for other, peer := range cfg.Peers {
		if other == name || peer.PublicKey == "" {
			continue
		}
		candidate, err := connectionpkg.NormalizePublicKey(peer.PublicKey)
		if err == nil && candidate == normalized {
			return fmt.Errorf("public key is already registered as peer %q", other)
		}
	}
	return nil
}

// errSSHUnreachable marks a probe failure that ssh could not even get a
// connection refused/accepted answer for (DNS failure, connection refused,
// timeout, host key mismatch) as opposed to a clean auth rejection, which
// means the destination is up but this installation's key isn't trusted yet.
var errSSHUnreachable = errors.New("ssh destination unreachable")

func probeExistingAccess(ctx context.Context, destination string) error {
	cmd, err := androidexec.CommandContext(ctx, connectionSSH, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none", destination, "true")
	if err != nil {
		return fmt.Errorf("%w: %w", errSSHUnreachable, err)
	}
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		detail = err.Error()
	}
	if strings.Contains(detail, "Permission denied") {
		return fmt.Errorf("%s", detail)
	}
	return fmt.Errorf("%w: %s", errSSHUnreachable, detail)
}

func installRemoteGrant(ctx context.Context, destination, localName, localAddress, publicKey string) error {
	if err := peername.Validate(localName); err != nil {
		return err
	}
	if !safeBootstrapAddress(localAddress) {
		return errors.New("local bootstrap address contains unsafe characters")
	}
	cmd, err := androidexec.CommandContext(ctx, connectionSSH, "-T", "-o", "ControlMaster=no", "-o", "ControlPath=none", destination, connectionBinary, "connection", "add", localName, localAddress, "--key", "-")
	if err != nil {
		return err
	}
	cmd.Stdin = strings.NewReader(publicKey + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remote connection add: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// unadvertisableHostnames are hostnames that resolve to "this machine" only
// from the machine itself; printed as a peer address they would send the
// remote side back to itself instead of to us.
var unadvertisableHostnames = map[string]bool{
	"localhost":     true,
	"127.0.0.1":     true,
	"::1":           true,
	"ip6-localhost": true,
}

// installationAddress returns this installation's peer name and the address
// to advertise it under, plus whether that address is actually likely to
// reach this machine from elsewhere. os.Hostname() commonly returns
// "localhost" (notably under Termux) or a bare LAN name a remote peer can't
// resolve, so callers must surface the false case rather than presenting
// the address as trustworthy.
func installationAddress() (string, string, bool) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	name = strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, name)
	knownGood := !unadvertisableHostnames[strings.ToLower(host)]
	return name, host, knownGood
}

func safeBootstrapAddress(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || strings.ContainsRune("@._:-", character)) {
			return false
		}
	}
	return true
}

func currentLoginShell() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", err
	}
	contents, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == current.Username {
			return fields[6], nil
		}
	}
	return "", errors.New("current account is absent from /etc/passwd")
}
