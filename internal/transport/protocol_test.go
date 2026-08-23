//go:build linux

package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"l2syncd/internal/connection"
	"l2syncd/internal/lock"
	"l2syncd/internal/metadata"
	"l2syncd/internal/sharepath"
)

var protocolTestHash = strings.Repeat("a", 64)

func TestReadSharesRequiresEndMarker(t *testing.T) {
	var stream bytes.Buffer
	writer := frameWriter{w: &stream}
	if err := writer.write(message{Type: messageShare, Share: "notes"}); err != nil {
		t.Fatal(err)
	}

	_, err := readShares(&stream)
	if !errors.Is(err, errUnexpectedEnd) {
		t.Fatalf("readShares error = %v, want truncated listing error", err)
	}
}

func TestFileListingCarriesMetadataAndDirectories(t *testing.T) {
	manifest := metadata.Manifest{Mode: 0o640, Mtime: time.Unix(100, 200), Xattrs: map[string][]byte{"user.test": []byte("value")}, ACLAccess: []byte("raw-acl")}
	var stream bytes.Buffer
	writer := frameWriter{w: &stream}
	if err := writer.write(message{Type: messageFile, Path: "folder", Directory: true, Metadata: manifest}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(message{Type: messageFile, Path: "folder/file", Size: 4, Hash: protocolTestHash, Metadata: manifest}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(message{Type: messageEnd}); err != nil {
		t.Fatal(err)
	}
	entries, err := readFiles(&stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || !entries[0].Directory || entries[1].Directory || !metadata.Equal(entries[1].Metadata, manifest) {
		t.Fatalf("entries = %#v, want metadata-bearing directory and file", entries)
	}
}

func TestServePeerReuseTransfersNoContentFrames(t *testing.T) {
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(100, 0)}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageReuseFile, Share: "notes", Path: "new", Hash: protocolTestHash, Metadata: manifest}); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	called := false
	err := Serve(&request, &response, Callbacks{
		ReuseFile: func(share, path, hash string, got metadata.Manifest) (bool, error) {
			called = true
			if share != "notes" || path != "new" || hash != protocolTestHash || !metadata.Equal(got, manifest) {
				t.Fatalf("reuse request = %q %q %q %#v", share, path, hash, got)
			}
			return true, nil
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("reuse callback was not called")
	}
	frame, err := (frameReader{r: bufio.NewReader(&response)}).read()
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != messageReused {
		t.Fatalf("response = %q, want reused", frame.Type)
	}
}

func TestReadSharesReturnsOnlyCompleteListing(t *testing.T) {
	var stream bytes.Buffer
	writer := frameWriter{w: &stream}
	for _, item := range []message{
		{Type: messageShare, Share: "notes"},
		{Type: messageShare, Share: "photos"},
		{Type: messageEnd},
	} {
		if err := writer.write(item); err != nil {
			t.Fatal(err)
		}
	}

	shares, err := readShares(&stream)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"notes", "photos"}; len(shares) != len(want) || shares[0] != want[0] || shares[1] != want[1] {
		t.Fatalf("shares = %#v, want %#v", shares, want)
	}
}

func TestReadSharesRejectsUnexpectedMessage(t *testing.T) {
	var stream bytes.Buffer
	if err := (frameWriter{w: &stream}).write(message{Type: messageFile}); err != nil {
		t.Fatal(err)
	}

	if _, err := readShares(&stream); err == nil {
		t.Fatal("readShares error = nil, want unexpected-message error")
	}
}

func TestReadFilesRequiresEndMarker(t *testing.T) {
	var stream bytes.Buffer
	if err := (frameWriter{w: &stream}).write(message{Type: messageFile, Path: "a.txt", Size: 1, Hash: protocolTestHash}); err != nil {
		t.Fatal(err)
	}

	_, err := readFiles(&stream)
	if !errors.Is(err, errUnexpectedEnd) {
		t.Fatalf("readFiles error = %v, want truncated listing error", err)
	}
}

func TestServePeerSortsAndTerminatesFileListing(t *testing.T) {
	var request bytes.Buffer
	if err := writeListFilesRequest(&request, "notes"); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	files := []PeerFile{{Path: "z.txt", Size: 3, Hash: protocolTestHash}, {Path: "a.txt", Size: 1, Hash: protocolTestHash}}
	err := Serve(&request, &response, Callbacks{ListFiles: func(share string) ([]PeerFile, error) {
		if share != "notes" {
			t.Fatalf("file lister share = %q, want notes", share)
		}
		return files, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readFiles(&response)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "a.txt" || got[1].Path != "z.txt" {
		t.Fatalf("files = %#v, want sorted file listing", got)
	}
}

func TestServePeerDispatchesFileListing(t *testing.T) {
	var request bytes.Buffer
	if err := writeListFilesRequest(&request, "notes"); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	err := Serve(&request, &response, Callbacks{ListFiles: func(share string) ([]PeerFile, error) {
		if share != "notes" {
			t.Fatalf("file lister share = %q, want notes", share)
		}
		return []PeerFile{{Path: "notes/a.txt", Size: 4, Hash: protocolTestHash}}, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	files, err := readFiles(&response)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "notes/a.txt" || files[0].Size != 4 {
		t.Fatalf("files = %#v, want one dispatched file", files)
	}
}

func TestServeReadFileCallbackCannotFollowShareSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "leaf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ancestor")); err != nil {
		t.Fatal(err)
	}
	callbacks := Callbacks{ReadFile: func(_ string, relative string) (io.ReadCloser, error) {
		return sharepath.OpenRegular(root, relative)
	}}
	for _, relative := range []string{"leaf", "ancestor/secret"} {
		t.Run(relative, func(t *testing.T) {
			var request bytes.Buffer
			if err := (frameWriter{w: &request}).write(message{Type: messageReadFile, Share: "notes", Path: relative}); err != nil {
				t.Fatal(err)
			}
			if err := Serve(&request, io.Discard, callbacks, nil); err == nil {
				t.Fatal("protocol read followed a share symlink")
			}
		})
	}
	var request, response bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageReadFile, Share: "notes", Path: "regular"}); err != nil {
		t.Fatal(err)
	}
	if err := Serve(&request, &response, callbacks, nil); err != nil {
		t.Fatal(err)
	}
	reader := frameReader{r: bufio.NewReader(&response)}
	chunk, err := reader.read()
	if err != nil || chunk.Type != messageChunk || string(chunk.Data) != "inside" {
		t.Fatalf("regular read chunk = %#v, %v", chunk, err)
	}
	end, err := reader.read()
	if err != nil || end.Type != messageEnd {
		t.Fatalf("regular read end = %#v, %v", end, err)
	}
}

func TestReadFilesRejectsUnsafePath(t *testing.T) {
	var stream bytes.Buffer
	if err := (frameWriter{w: &stream}).write(message{Type: messageFile, Path: "../outside", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFiles(&stream); err == nil {
		t.Fatal("readFiles error = nil, want unsafe path error")
	}
}

func TestValidateRelativePath(t *testing.T) {
	for _, value := range []string{"", ".", "/absolute", "../outside", "folder/../outside", "folder//file"} {
		t.Run(value, func(t *testing.T) {
			if err := ValidateRelativePath(value); err == nil {
				t.Fatalf("ValidateRelativePath(%q) = nil", value)
			}
		})
	}
	if err := ValidateRelativePath("folder/file.txt"); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
}

func TestReadFilesRejectsInvalidHashesDuplicatesAndTypeCollisions(t *testing.T) {
	tests := map[string][]message{
		"short hash": {
			{Type: messageFile, Path: "a", Size: 1, Hash: "abc"},
		},
		"non-hex hash": {
			{Type: messageFile, Path: "a", Size: 1, Hash: strings.Repeat("z", 64)},
		},
		"duplicate": {
			{Type: messageFile, Path: "a", Directory: true},
			{Type: messageFile, Path: "a", Size: 1, Hash: protocolTestHash},
		},
		"file ancestor": {
			{Type: messageFile, Path: "a", Size: 1, Hash: protocolTestHash},
			{Type: messageFile, Path: "a/b", Size: 1, Hash: protocolTestHash},
		},
		"file replaces ancestor": {
			{Type: messageFile, Path: "a/b", Size: 1, Hash: protocolTestHash},
			{Type: messageFile, Path: "a", Size: 1, Hash: protocolTestHash},
		},
	}
	for name, entries := range tests {
		t.Run(name, func(t *testing.T) {
			var stream bytes.Buffer
			writer := frameWriter{w: &stream}
			for _, entry := range entries {
				if err := writer.write(entry); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.write(message{Type: messageEnd}); err != nil {
				t.Fatal(err)
			}
			if _, err := readFiles(&stream); err == nil {
				t.Fatal("readFiles accepted invalid listing")
			}
		})
	}
}

func TestWriteAndReuseRequireSHA256HashesBeforeConnecting(t *testing.T) {
	if err := WriteFile(context.Background(), Endpoint{Address: "peer"}, "notes", "a", nil, "short", metadata.Manifest{}); err == nil {
		t.Fatal("WriteFile accepted invalid hash")
	}
	if _, err := ReuseFile(context.Background(), Endpoint{Address: "peer"}, "notes", "a", "short", metadata.Manifest{}); err == nil {
		t.Fatal("ReuseFile accepted invalid hash")
	}
}

func TestServeWriteRejectsUnsafePeerAndDeclaredSizeOverflow(t *testing.T) {
	writeRequest := func(peer string, size int64, chunks ...[]byte) bytes.Buffer {
		var request bytes.Buffer
		writer := frameWriter{w: &request}
		if err := writer.write(message{Type: messageWriteFile, Share: "notes", Path: "a", Peer: peer, Size: size, Hash: protocolTestHash}); err != nil {
			t.Fatal(err)
		}
		for _, chunk := range chunks {
			if err := writer.write(message{Type: messageChunk, Data: chunk}); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.write(message{Type: messageEnd}); err != nil {
			t.Fatal(err)
		}
		return request
	}
	callbacks := Callbacks{
		WriteFile: func(string, string, string, metadata.Manifest, io.Reader) error {
			t.Fatal("write callback called for invalid request")
			return nil
		},
		WriteConflict: func(string, string, string, string, metadata.Manifest, io.Reader) error {
			t.Fatal("conflict callback called for invalid request")
			return nil
		},
	}
	unsafe := writeRequest("../outside", 0)
	if err := Serve(&unsafe, io.Discard, callbacks, nil); err == nil {
		t.Fatal("Serve accepted unsafe conflict peer")
	}
	overflow := writeRequest("", 1, []byte("ab"))
	if err := Serve(&overflow, io.Discard, callbacks, nil); err == nil {
		t.Fatal("Serve accepted content beyond declared size")
	}
}

func TestSSHArgumentsReuseControlConnectionExceptForBulkTransfers(t *testing.T) {
	configPath := filepath.Join("tmp", "runtime", "l2sync", "ssh-%C")
	controlPath := "phone"
	control := sshArguments(configPath, controlPath, "/key", false)
	wantControlPath := "ControlPath=" + controlPath
	if !slices.Contains(control, "ControlMaster=auto") || !slices.Contains(control, "ControlPersist="+sshControlPersist) || !slices.Contains(control, wantControlPath) || !slices.Contains(control, "BatchMode=yes") || !slices.Contains(control, "IdentitiesOnly=yes") || !slices.Contains(control, "-T") || !slices.Contains(control, "/key") {
		t.Fatalf("control SSH arguments = %#v", control)
	}
	bulk := sshArguments(configPath, controlPath, "/key", true)
	if !slices.Contains(bulk, "ControlPath=none") || !slices.Contains(bulk, "ControlMaster=no") {
		t.Fatalf("bulk SSH arguments = %#v, want ControlPath=none", bulk)
	}
}

func TestControlSocketSelectionDisablesMultiplexingForLongOrUnsafeRuntimePath(t *testing.T) {
	valid, err := os.MkdirTemp("/tmp", "l2r-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(valid) })
	t.Setenv("XDG_RUNTIME_DIR", valid)
	if path := safeControlSocketPath(); path == "" {
		t.Fatal("private short runtime directory did not enable multiplexing")
	}
	long := filepath.Join(t.TempDir(), strings.Repeat("segment", 20))
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", long)
	if path := safeControlSocketPath(); path != "" {
		t.Fatalf("long runtime path selected control socket %q", path)
	}
	arguments := sshArguments("config", safeControlSocketPath(), "/key", false)
	if !slices.Contains(arguments, "ControlMaster=no") || !slices.Contains(arguments, "ControlPath=none") {
		t.Fatalf("long-path SSH arguments = %#v", arguments)
	}
	unsafe := t.TempDir()
	if err := os.Chmod(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", unsafe)
	if path := safeControlSocketPath(); path != "" {
		t.Fatalf("unsafe runtime directory selected control socket %q", path)
	}
}

func TestServeRequiresAndValidatesPinnedHello(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	paths, err := connection.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	key, err := connection.EnsureKey(paths)
	if err != nil {
		t.Fatal(err)
	}
	var request bytes.Buffer
	writer := frameWriter{w: &request}
	if err := writer.write(message{Type: messageHello, Key: key + " caller-comment"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.write(message{Type: messageListShares}); err != nil {
		t.Fatal(err)
	}
	called := false
	var response bytes.Buffer
	if err := Serve(&request, &response, Callbacks{ListShares: func() ([]string, error) { return []string{"notes"}, nil }}, &Handshake{ExpectedPeerKey: key, LocalPublicKey: key, OnSuccess: func() error { called = true; return nil }}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("handshake success callback was not called")
	}
	reader := frameReader{r: bufio.NewReader(&response)}
	if reply, err := reader.read(); err != nil || reply.Type != messageHelloReply {
		t.Fatalf("hello reply = %#v, %v", reply, err)
	}
	shares, err := readShares(reader.r)
	if err != nil || !slices.Equal(shares, []string{"notes"}) {
		t.Fatalf("shares = %#v, %v", shares, err)
	}

	otherRoot := t.TempDir()
	t.Setenv("HOME", otherRoot)
	otherPaths, _ := connection.DefaultPaths()
	other, err := connection.EnsureKey(otherPaths)
	if err != nil {
		t.Fatal(err)
	}
	request.Reset()
	_ = (frameWriter{w: &request}).write(message{Type: messageHello, Key: other})
	_ = (frameWriter{w: &request}).write(message{Type: messageListShares})
	if err := Serve(&request, io.Discard, Callbacks{}, &Handshake{ExpectedPeerKey: key, LocalPublicKey: key}); err == nil {
		t.Fatal("Serve accepted a hello with the wrong key")
	}
}

func TestServeBindShareUsesAuthenticatedConnectionContext(t *testing.T) {
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageBindShare, Share: "notes"}); err != nil {
		t.Fatal(err)
	}
	bound := ""
	var response bytes.Buffer
	if err := Serve(&request, &response, Callbacks{BindShare: func(share string) (bool, error) { bound = share; return true, nil }}, nil); err != nil {
		t.Fatal(err)
	}
	if bound != "notes" {
		t.Fatalf("bound share = %q", bound)
	}
	reply, err := (frameReader{r: bufio.NewReader(&response)}).read()
	if err != nil || reply.Type != messageEnd || !reply.Created {
		t.Fatalf("bind reply = %#v, %v", reply, err)
	}
}

func TestServeRequestCycleReturnsActualInitiatorResult(t *testing.T) {
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageRequestCycle, Share: "notes"}); err != nil {
		t.Fatal(err)
	}
	requested := ""
	var response bytes.Buffer
	err := Serve(&request, &response, Callbacks{RequestCycle: func(share string) (int, error) {
		requested = share
		return 7, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := (frameReader{r: bufio.NewReader(&response)}).read()
	if err != nil || reply.Type != messageEnd || reply.Actions != 7 || requested != "notes" {
		t.Fatalf("cycle reply = %#v, requested = %q, err = %v", reply, requested, err)
	}
}

func TestServeChecksExactConflictDestination(t *testing.T) {
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageConflictCheck, Share: "notes", Path: "a.txt", Peer: "20260823-120000-aaaaaaaaaaaa"}); err != nil {
		t.Fatal(err)
	}
	var response bytes.Buffer
	gotSuffix := ""
	callbacks := Callbacks{ConflictCopyExists: func(share, relative, suffix string) (bool, error) {
		if share != "notes" || relative != "a.txt" {
			t.Fatalf("collision request = %q/%q", share, relative)
		}
		gotSuffix = suffix
		return true, nil
	}}
	if err := Serve(&request, &response, callbacks, nil); err != nil {
		t.Fatal(err)
	}
	reply, err := (frameReader{r: bufio.NewReader(&response)}).read()
	if err != nil || !reply.Exists || gotSuffix != "20260823-120000-aaaaaaaaaaaa" {
		t.Fatalf("collision reply = %#v, suffix = %q, err = %v", reply, gotSuffix, err)
	}
}

func TestServeUnbindShareDispatchesIdempotentCompensation(t *testing.T) {
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageUnbindShare, Share: "notes"}); err != nil {
		t.Fatal(err)
	}
	unbound := ""
	var response bytes.Buffer
	if err := Serve(&request, &response, Callbacks{UnbindShare: func(share string) error { unbound = share; return nil }}, nil); err != nil {
		t.Fatal(err)
	}
	if unbound != "notes" {
		t.Fatalf("unbound share = %q", unbound)
	}
}

func TestSSHFailureClassificationSeparatesRemoteRejectionFromTransport(t *testing.T) {
	applicationErr := exitError(t, 1)
	if err := classifySSHFailure("phone", applicationErr, nil, nil); IsError(err) {
		t.Fatalf("remote application failure classified as transport: %v", err)
	}
	transportErr := classifySSHFailure("phone", exitError(t, 255), nil, []byte("unix_listener: path too long\n"))
	if !IsError(transportErr) {
		t.Fatalf("SSH reachability failure not classified as transport: %v", transportErr)
	}
	if !strings.Contains(transportErr.Error(), "unix_listener: path too long") {
		t.Fatalf("SSH transport error omitted bounded stderr: %v", transportErr)
	}
	deadlineErr := classifySSHFailure("phone", errors.New("killed"), context.DeadlineExceeded, nil)
	if !IsError(deadlineErr) {
		t.Fatalf("deadline failure not classified as transport: %v", deadlineErr)
	}
	lockedErr := classifySSHFailure("phone", exitError(t, remoteLockedExitCode), nil, nil)
	if !errors.Is(lockedErr, lock.ErrTimeout) || IsError(lockedErr) {
		t.Fatalf("remote lock failure classification = %v", lockedErr)
	}
}

func TestSSHStderrCaptureIsBoundedAndSanitized(t *testing.T) {
	var buffer boundedBuffer
	buffer.limit = sshStderrLimit
	payload := []byte("line-one\n\x1bsecret\tssh-ed25519 AAAA_PRIVATEISH " + strings.Repeat("x", sshStderrLimit*2))
	if written, err := buffer.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("bounded write = %d, %v", written, err)
	}
	if len(buffer.Bytes()) != sshStderrLimit {
		t.Fatalf("captured stderr bytes = %d", len(buffer.Bytes()))
	}
	clean := sanitizeSSHStderr(buffer.Bytes())
	if strings.ContainsAny(clean, "\n\t\x1b") || strings.Contains(clean, "AAAA_PRIVATEISH") || utf8.RuneCountInString(clean) > sshStderrExcerpt+1 {
		t.Fatalf("sanitized stderr = %q", clean)
	}
}

func exitError(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("exit error = %v", err)
	}
	return exitErr
}
