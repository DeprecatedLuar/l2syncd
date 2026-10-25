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
	"sync"
	"text/tabwriter"
	"unicode"

	"golang.org/x/term"

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
	connectionBinary    = "l2sync"

	connectionAddUsage       = "usage: l2sync connection add <name> [destination] [--key <pubkey>] [--address <user@host>]"
	connectionAddedMessage   = "peer %q added"
	connectionPresentMessage = "peer %q already present"
	suppliedKeyLimit         = 16 << 10

	flagPrefix  = "--"
	keyFlag     = "--key"
	addressFlag = "--address"
	forceFlag   = "--force"
	stdinMarker = "-"
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
	connectionProbe        = probeExistingAccess
	connectionInstall      = installRemoteGrant
	connectionRemoteRemove = removeRemotePeer
	connectionExchange     = transport.Exchange
	connectionListShares   = transport.ListShares
	loginShell             = currentLoginShell
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
	request, err := parseConnectionAdd(args, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	cfg, err := loadConfigWithoutFolderPreflight()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	if request.key != "" {
		return acceptPeerKey(cfg, request, stdout, stderr)
	}
	return dialPeer(cfg, request, stdout, stderr)
}

// acceptPeerKey grants a peer's key restricted access here. With no
// destination the peer is key-only until it connects and its address is
// learned through verify-return.
func acceptPeerKey(cfg config.Config, request connectionAddRequest, stdout, stderr io.Writer) int {
	existing, existed := cfg.Peers[request.name]
	if existed && (existing.PublicKey != "" && existing.PublicKey != request.key ||
		request.destination != "" && existing.Address != "" && existing.Address != request.destination) {
		fmt.Fprintf(stderr, "l2sync: peer %q already exists with different connection data\n", request.name)
		return connectionExitError
	}
	if err := rejectDuplicatePeerKey(cfg, request.name, request.key); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return connectionExitError
	}
	paths, localKey, ok := resolveLocalKey(stderr, "load")
	if !ok {
		return connectionExitError
	}
	if localKey == request.key {
		fmt.Fprintln(stderr, "l2sync: peer public key is this installation's key")
		return connectionExitError
	}
	peer := config.Peer{Address: existing.Address, Port: existing.Port, PublicKey: request.key}
	if request.destination != "" {
		peer.Address = request.destination
	}
	if err := storePeerLocked(request.name, peer); err != nil {
		fmt.Fprintf(stderr, "l2sync: save peer: %v\n", err)
		return connectionExitError
	}
	if err := connectionpkg.AddGrant(paths.AuthorizedKeys, request.name, request.key); err != nil {
		fmt.Fprintf(stderr, "l2sync: install restricted grant: %v\n", errors.Join(err, revertAcceptedPeer(request.name, peer, existing, existed)))
		return connectionExitError
	}
	if shell, err := loginShell(); err == nil && filepath.Base(shell) == "bash" {
		fmt.Fprintf(stderr, "l2sync: warning: login shell %q sources startup files before SSH forced commands; use a dedicated sync account for hardened isolation\n", shell)
	}
	message := connectionAddedMessage
	if existed {
		message = connectionPresentMessage
	}
	fmt.Fprintf(stdout, message+"\n", request.name)
	return connectionExitOK
}

// revertAcceptedPeer undoes the entry acceptPeerKey stored, leaving any
// concurrent change to the entry untouched.
func revertAcceptedPeer(name string, stored, previous config.Peer, existed bool) error {
	return updateConfigLocked(func(current *config.Config) error {
		if latest, exists := current.Peers[name]; !exists || latest != stored {
			return nil
		}
		if existed {
			current.Peers[name] = previous
		} else {
			delete(current.Peers, name)
		}
		return nil
	})
}

// dialPeer registers a peer reached over SSH and proves both directions:
// this side's key works there and the peer can dial back. A failed run
// removes what it created locally and remotely.
func dialPeer(cfg config.Config, request connectionAddRequest, stdout, stderr io.Writer) int {
	ctx := context.Background()
	existing, existed := cfg.Peers[request.name]
	if existed && existing.Address != request.destination {
		fmt.Fprintf(stderr, "l2sync: peer %q already exists with different connection data\n", request.name)
		return connectionExitError
	}
	if existed && existing.PublicKey != "" {
		if err := storePeerLocked(request.name, existing); err != nil {
			fmt.Fprintf(stderr, "l2sync: verify active peer: %v\n", err)
			return connectionExitError
		}
		return connectionExitOK
	}
	if existed {
		// An accepted invite makes the l2sync key work before any login access.
		if _, err := activatePeer(ctx, cfg, request.name, request.returnAddress); err == nil {
			return connectionExitOK
		} else if !transport.IsAuthError(err) {
			fmt.Fprintf(stderr, "l2sync: %v\n", err)
			return connectionExitError
		}
	}
	_, localKey, ok := resolveLocalKey(stderr, "prepare")
	if !ok {
		return connectionExitError
	}
	localName := installationName()
	probeErr := connectionProbe(ctx, request.destination)
	if probeErr != nil && errors.Is(probeErr, errSSHUnreachable) {
		fmt.Fprintf(stderr, "l2sync: %s is unreachable via SSH: %v\n", request.destination, probeErr)
		return connectionExitError
	}
	if !existed {
		cfg.Peers[request.name] = config.Peer{Address: request.destination}
		if err := storePeerLocked(request.name, cfg.Peers[request.name]); err != nil {
			fmt.Fprintf(stderr, "l2sync: save pending peer: %v\n", err)
			return connectionExitError
		}
	}
	removeLocal := func() error {
		if existed {
			return nil
		}
		return removePendingPeer(request.name)
	}
	if probeErr != nil {
		command := fmt.Sprintf("l2sync connection add %s --key %q", localName, localKey)
		if isTerminalWriter(stdout) {
			command = ansiBlue + command + ansiReset
		}
		fmt.Fprintf(stdout, "%s is reachable but doesn't have your key yet. Have someone run this there:\n\n  %s\n\nThen run this command again to finish.\n", request.destination, command)
		return connectionExitOK
	}
	remoteCreated, err := connectionInstall(ctx, request.destination, localName, localKey)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: install remote restricted grant: %v\n", errors.Join(err, removeLocal()))
		return connectionExitError
	}
	if _, err := activatePeer(ctx, cfg, request.name, request.returnAddress); err != nil {
		var remoteCleanup error
		if remoteCreated {
			if removeErr := connectionRemoteRemove(ctx, request.destination, localName); removeErr != nil {
				remoteCleanup = fmt.Errorf("grant left in %s's authorized_keys: %w", request.destination, removeErr)
			}
		}
		fmt.Fprintf(stderr, "l2sync: %v\n", errors.Join(err, remoteCleanup, removeLocal()))
		return connectionExitError
	}
	return connectionExitOK
}

// removePendingPeer deletes name only while it is still pending.
func removePendingPeer(name string) error {
	return updateConfigLocked(func(current *config.Config) error {
		if peer, exists := current.Peers[name]; exists && peer.PublicKey == "" {
			delete(current.Peers, name)
		}
		return nil
	})
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
	names := sortedKeys(cfg.Peers)
	symbols := make([]string, len(names))
	var group sync.WaitGroup
	for i, name := range names {
		group.Add(1)
		go func() {
			defer group.Done()
			symbols[i] = connectionStatusSymbol(cfg, name, cfg.Peers[name])
		}()
	}
	group.Wait()
	rows := make([]row, 0, len(names))
	for i, name := range names {
		rows = append(rows, row{name: name, symbol: symbols[i], peer: cfg.Peers[name]})
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
	// located from config alone.
	folderIDs := make(map[string]string, len(remoteTargets))
	for _, remoteName := range remoteTargets {
		if marker, markerErr := guard.ReadMarker(cfg.Remote[remoteName].Path); markerErr == nil {
			folderIDs[remoteName] = marker.ID
		}
	}

	paths, err := connectionpkg.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve authorized_keys: %v\n", err)
		return connectionExitError
	}
	if peer.PublicKey != "" {
		if err := connectionpkg.RemoveGrant(paths.AuthorizedKeys, name, peer.PublicKey); err != nil {
			fmt.Fprintf(stderr, "l2sync: remove restricted grant: %v; retry connection rm\n", err)
			return connectionExitError
		}
	}
	if peer.Address != "" {
		host := config.AddressHost(peer.Address)
		if _, shared := peerUsingEndpoint(&cfg, name, host, peer.Port); !shared {
			if err := connectionpkg.UnpinHostKeys(paths.KnownHosts, host, peer.Port); err != nil {
				fmt.Fprintf(stderr, "l2sync: remove pinned host keys: %v; retry connection rm\n", err)
				return connectionExitError
			}
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
		if args[1] != forceFlag {
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

type connectionAddRequest struct {
	name, destination, key, returnAddress string
}

func parseConnectionAdd(args []string, stdin io.Reader) (connectionAddRequest, error) {
	if len(args) < 1 {
		return connectionAddRequest{}, errors.New(connectionAddUsage)
	}
	request := connectionAddRequest{name: strings.ToLower(args[0])}
	if err := peername.Validate(request.name); err != nil {
		return connectionAddRequest{}, err
	}
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], flagPrefix) {
		request.destination, rest = rest[0], rest[1:]
	}
	for len(rest) > 0 {
		if len(rest) < 2 {
			return connectionAddRequest{}, errors.New(connectionAddUsage)
		}
		switch rest[0] {
		case keyFlag:
			key, err := readSuppliedKey(rest[1], stdin)
			if err != nil {
				return connectionAddRequest{}, err
			}
			request.key = key
		case addressFlag:
			request.returnAddress = rest[1]
		default:
			return connectionAddRequest{}, errors.New(connectionAddUsage)
		}
		rest = rest[2:]
	}
	if request.key != "" && request.returnAddress != "" {
		return connectionAddRequest{}, errors.New("--address applies only when dialing a peer, not with --key")
	}
	if request.key == "" && request.destination == "" {
		request.destination = request.name
	}
	if request.destination != "" {
		if err := config.ValidatePeerAddress(request.destination); err != nil {
			return connectionAddRequest{}, fmt.Errorf("invalid SSH destination: %w", err)
		}
	}
	return request, nil
}

func readSuppliedKey(value string, stdin io.Reader) (string, error) {
	if value == stdinMarker {
		contents, err := io.ReadAll(io.LimitReader(stdin, suppliedKeyLimit))
		if err != nil {
			return "", fmt.Errorf("read public key: %w", err)
		}
		value = string(contents)
	}
	return connectionpkg.NormalizePublicKey(value)
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
	cmd, err := transport.LoginSSHCommand(ctx, destination, "true")
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

func removeRemotePeer(ctx context.Context, destination, localName string) error {
	cmd, err := transport.LoginSSHCommand(ctx, destination, connectionBinary, "connection", "rm", localName, forceFlag)
	if err != nil {
		return err
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		return transport.RemoteExitError(destination, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func installRemoteGrant(ctx context.Context, destination, localName, publicKey string) (bool, error) {
	if err := peername.Validate(localName); err != nil {
		return false, err
	}
	cmd, err := transport.LoginSSHCommand(ctx, destination, connectionBinary, "connection", "add", localName, keyFlag, stdinMarker)
	if err != nil {
		return false, err
	}
	cmd.Stdin = strings.NewReader(publicKey + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, transport.RemoteExitError(destination, err, strings.TrimSpace(string(output)))
	}
	return strings.Contains(string(output), fmt.Sprintf(connectionAddedMessage, localName)), nil
}

// installationName is this machine's peer name as other installations see
// it: the hostname, lowercased, with unsupported characters replaced.
func installationName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, name)
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
