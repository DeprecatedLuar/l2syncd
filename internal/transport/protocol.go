//go:build linux

// Package transport contains the peer wire protocol and its SSH adapter.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"l2syncd/internal/config"
	"l2syncd/internal/connection"
	"l2syncd/internal/lock"
	"l2syncd/internal/metadata"
	"l2syncd/internal/peername"
	"l2syncd/internal/sharepath"
	"l2syncd/internal/vector"
)

const (
	frameHeaderSize = 4
	maxFrameSize    = 16 << 20

	messageListShares    = "list-shares"
	messageHello         = "hello"
	messageHelloReply    = "hello-reply"
	messagePing          = "ping"
	messageBindShare     = "bind-share"
	messageUnbindShare   = "unbind-share"
	messageListFiles     = "list-files"
	messageReadFile      = "read-file"
	messageWriteFile     = "write-file"
	messageConflictCopy  = "write-conflict-copy"
	messageConflictCheck = "check-conflict-copy"
	messageRequestCycle  = "request-cycle"
	messageDeleteFile    = "delete-file"
	messageApplyDir      = "apply-directory"
	messageDeleteDir     = "delete-directory"
	messageReuseFile     = "reuse-file"
	messageMergeVector   = "merge-vector"
	messageShare         = "share"
	messageFile          = "file"
	messageEnd           = "end"
	messageChunk         = "chunk"
	messageReused        = "reused"
	messageReuseMiss     = "reuse-miss"
	sshCommand           = "ssh"
	remoteBinary         = "l2sync"
	fileChunkSize        = 1 << 20
	sshControlPersist    = "60s"
	remoteLockedExitCode = 4
	unixSocketPathLimit  = 104
	controlHashLength    = 40
	sshStderrLimit       = 4096
	sshStderrExcerpt     = 512
	sshConfigLimit       = 1 << 20
	sshConfigPrefix      = "l2sync-ssh-"
	sshConfigHost        = "l2sync-peer"
)

var errUnexpectedEnd = errors.New("peer listing ended without an end-of-stream marker")

// Error identifies a failure to reach a peer or complete its protocol stream.
// Remote application errors, such as a rejected marker, are deliberately not
// transport errors.
type Error struct {
	err  error
	auth bool
}

func (err *Error) Error() string { return err.err.Error() }
func (err *Error) Unwrap() error { return err.err }

// IsError reports whether err represents peer reachability or a truncated
// transport stream.
func IsError(err error) bool {
	var transportErr *Error
	return errors.As(err, &transportErr)
}

// IsAuthError reports whether err represents an SSH public-key rejection
// specifically, as opposed to any other reachability failure (timeout, DNS,
// connection refused). A rejected key means the peer's authorized_keys entry
// is gone or invalid — most commonly because the peer ran "connection rm".
func IsAuthError(err error) bool {
	var transportErr *Error
	return errors.As(err, &transportErr) && transportErr.auth
}

// NewAuthErrorForTest builds an error satisfying IsAuthError, for tests of
// code that branches on peer key rejection without exercising real SSH.
func NewAuthErrorForTest(message string) error {
	return &Error{err: errors.New(message), auth: true}
}

type message struct {
	Type      string            `json:"type"`
	Share     string            `json:"share,omitempty"`
	Id        string            `json:"id,omitempty"`
	Path      string            `json:"path,omitempty"`
	Size      int64             `json:"size,omitempty"`
	Hash      string            `json:"hash,omitempty"`
	Data      []byte            `json:"data,omitempty"`
	Peer      string            `json:"peer,omitempty"`
	Key       string            `json:"key,omitempty"`
	Metadata  metadata.Manifest `json:"metadata,omitempty"`
	Directory bool              `json:"directory,omitempty"`
	Created   bool              `json:"created,omitempty"`
	Exists    bool              `json:"exists,omitempty"`
	Actions   int               `json:"actions,omitempty"`
	// Version is the version vector attached to a listing entry, or the
	// resulting vector a mutation's target path must hold once it lands
	// (implementation-plan.md Phase C: every action carries its result
	// vector so the receiving side never has to re-derive one).
	Version vector.Vector `json:"version,omitempty"`
	// Deleted marks a listing entry as a tombstone: no content fields are
	// meaningful when this is set (concept.md 4.2).
	Deleted   bool      `json:"deleted,omitempty"`
	DeletedAt time.Time `json:"deleted_at"`
}

// Endpoint is a pinned peer and the local installation credential used for
// every SSH protocol connection.
type Endpoint struct {
	Name            string
	Address         string
	PublicKey       string
	LocalPublicKey  string
	PrivateKey      string
	AuthorizedKeys  string
	AcceptPublicKey func(string) error
}

// Handshake configures the authenticated server-side hello exchange.
type Handshake struct {
	ExpectedPeerKey string
	LocalPublicKey  string
}

// PeerFile is one entry reported by a peer listing: a live regular file, a
// directory, or a tombstone. A tombstone (Deleted true) carries no content
// fields (concept.md 4.2).
type PeerFile struct {
	Path      string
	Size      int64
	Hash      string
	Metadata  metadata.Manifest
	Directory bool
	Deleted   bool
	DeletedAt time.Time
	Version   vector.Vector
}

// Callbacks are the filesystem operations available to the peer protocol.
// A nil field disables its corresponding request. Every mutation callback
// that persists an index entry receives the exact vector.Vector that entry
// must hold once the mutation lands, so the receiving side never re-derives
// one (implementation-plan.md Phase C).
type Callbacks struct {
	ListShares         func() ([]string, error)
	BindShare          func(string) (bool, error)
	UnbindShare        func(string) error
	ListFiles          func(share, expectedID string) ([]PeerFile, string, error)
	ReadFile           func(string, string) (io.ReadCloser, error)
	WriteFile          func(share, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error
	DeleteFile         func(share, relative string, vec vector.Vector) error
	WriteConflict      func(share, relative, loser, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error
	WriteConflictCopy  func(share, relative, suffix, expectedHash string, manifest metadata.Manifest, contents io.Reader) error
	ConflictCopyExists func(string, string, string) (bool, error)
	RequestCycle       func(string) (int, error)
	ReuseFile          func(share, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector) (bool, error)
	ApplyDirectory     func(string, string, metadata.Manifest) error
	DeleteDirectory    func(string, string) error
	// MergeVector advances share's index entry for relative to vec without
	// moving any bytes: the resolution for a concurrent-but-identical pair
	// (engine.Merge), where nothing else carries the vector to this peer.
	MergeVector func(share, relative string, vec vector.Vector) error
}

type frameWriter struct {
	w io.Writer
}

func (writer frameWriter) write(message message) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode peer message: %w", err)
	}
	if len(payload) > maxFrameSize {
		return fmt.Errorf("peer message is too large: %d bytes", len(payload))
	}
	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := writer.w.Write(header); err != nil {
		return fmt.Errorf("write peer message length: %w", err)
	}
	if _, err := writer.w.Write(payload); err != nil {
		return fmt.Errorf("write peer message: %w", err)
	}
	return nil
}

type frameReader struct {
	r *bufio.Reader
}

func (reader frameReader) read() (message, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(reader.r, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return message{}, errUnexpectedEnd
		}
		return message{}, fmt.Errorf("read peer message length: %w", err)
	}
	size := binary.BigEndian.Uint32(header)
	if size > maxFrameSize {
		return message{}, fmt.Errorf("peer message is too large: %d bytes", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader.r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return message{}, errUnexpectedEnd
		}
		return message{}, fmt.Errorf("read peer message: %w", err)
	}
	var result message
	if err := json.Unmarshal(payload, &result); err != nil {
		return message{}, fmt.Errorf("decode peer message: %w", err)
	}
	return result, nil
}

func writeListSharesRequest(writer io.Writer) error {
	return (frameWriter{w: writer}).write(message{Type: messageListShares})
}

// writeListFilesRequest asks a peer to list one share. expectedID, when
// non-empty, is this installation's folder identity for share: the identity
// exchanged before any listing (concept.md 5.9). Empty means the caller has
// not yet learned an id for this folder (join's first request).
func writeListFilesRequest(writer io.Writer, share, expectedID string) error {
	if share == "" {
		return errors.New("share name is empty")
	}
	return (frameWriter{w: writer}).write(message{Type: messageListFiles, Share: share, Id: expectedID})
}

func readShares(reader io.Reader) ([]string, error) {
	frames := frameReader{r: bufio.NewReader(reader)}
	shares := make([]string, 0)
	for {
		message, err := frames.read()
		if err != nil {
			return nil, err
		}
		switch message.Type {
		case messageShare:
			if message.Share == "" {
				return nil, errors.New("peer returned an empty share name")
			}
			shares = append(shares, message.Share)
		case messageEnd:
			return shares, nil
		default:
			return nil, fmt.Errorf("unexpected peer message %q", message.Type)
		}
	}
}

// readFiles returns the listed files and the provider's folder id, carried on
// the terminal end-of-stream message.
func readFiles(reader io.Reader) ([]PeerFile, string, error) {
	frames := frameReader{r: bufio.NewReader(reader)}
	files := make([]PeerFile, 0)
	seen := make(map[string]bool)
	for {
		message, err := frames.read()
		if err != nil {
			return nil, "", err
		}
		switch message.Type {
		case messageFile:
			if message.Path == "" {
				return nil, "", errors.New("peer returned an empty file path")
			}
			if err := ValidateRelativePath(message.Path); err != nil {
				return nil, "", err
			}
			if message.Size < 0 {
				return nil, "", fmt.Errorf("peer returned a negative file size for %q", message.Path)
			}
			if err := validateListingEntry(message.Path, message.Hash, message.Directory, message.Deleted, seen); err != nil {
				return nil, "", err
			}
			files = append(files, PeerFile{
				Path: message.Path, Size: message.Size, Hash: strings.ToLower(message.Hash), Metadata: message.Metadata,
				Directory: message.Directory, Deleted: message.Deleted, DeletedAt: message.DeletedAt, Version: message.Version,
			})
		case messageEnd:
			return files, message.Id, nil
		default:
			return nil, "", fmt.Errorf("unexpected peer message %q", message.Type)
		}
	}
}

// ListShares asks a peer for its locally offered shares over SSH.
func ListShares(ctx context.Context, endpoint Endpoint) ([]string, error) {
	if endpoint.Address == "" {
		return nil, errors.New("peer address is empty")
	}
	var request bytes.Buffer
	if err := writeListSharesRequest(&request); err != nil {
		return nil, err
	}
	output, err := runSSH(ctx, endpoint, false, request.Bytes())
	if err != nil {
		return nil, err
	}
	shares, err := readShares(bytes.NewReader(output))
	if err != nil {
		return nil, &Error{err: fmt.Errorf("read peer %q share listing: %w", endpoint.Address, err)}
	}
	return shares, nil
}

// ListFiles asks a peer for the regular files in one offered share.
// expectedID is this installation's known folder identity for share, or ""
// when it has none yet (join's first request for a not-yet-registered
// folder). When expectedID is non-empty and the peer's identity differs, this
// is a hard error naming both ids: reconciliation never proceeds on a name
// match alone (concept.md 5.9). The peer's identity is always returned so a
// first-time caller can record it.
func ListFiles(ctx context.Context, endpoint Endpoint, share, expectedID string) ([]PeerFile, string, error) {
	if endpoint.Address == "" {
		return nil, "", errors.New("peer address is empty")
	}
	var request bytes.Buffer
	if err := writeListFilesRequest(&request, share, expectedID); err != nil {
		return nil, "", err
	}
	output, err := runSSH(ctx, endpoint, false, request.Bytes())
	if err != nil {
		return nil, "", err
	}
	files, id, err := readFiles(bytes.NewReader(output))
	if err != nil {
		return nil, "", &Error{err: fmt.Errorf("read peer %q file listing: %w", endpoint.Address, err)}
	}
	if expectedID != "" && id != "" && id != expectedID {
		return nil, "", fmt.Errorf("folder %q identity mismatch: local id %q, peer %q id %q", share, expectedID, endpoint.Name, id)
	}
	return files, id, nil
}

// ReadFile retrieves one regular file from a peer after validating its path
// and hash. The response must terminate with an explicit end marker.
func ReadFile(ctx context.Context, endpoint Endpoint, share, relative, expectedHash string) ([]byte, error) {
	if endpoint.Address == "" || share == "" {
		return nil, errors.New("peer address and share are required")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return nil, err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageReadFile, Share: share, Path: relative}); err != nil {
		return nil, err
	}
	output, err := runSSH(ctx, endpoint, true, request.Bytes())
	if err != nil {
		return nil, err
	}
	reader := frameReader{r: bufio.NewReader(bytes.NewReader(output))}
	var contents bytes.Buffer
	for {
		frame, err := reader.read()
		if err != nil {
			return nil, &Error{err: fmt.Errorf("read peer %q file stream: %w", endpoint.Address, err)}
		}
		switch frame.Type {
		case messageChunk:
			if len(frame.Data) == 0 {
				return nil, errors.New("peer returned an empty file chunk")
			}
			if _, err := contents.Write(frame.Data); err != nil {
				return nil, fmt.Errorf("buffer peer file: %w", err)
			}
		case messageEnd:
			data := contents.Bytes()
			if expectedHash != "" && !strings.EqualFold(fmt.Sprintf("%x", sha256Sum(data)), expectedHash) {
				return nil, fmt.Errorf("peer file %q hash mismatch", relative)
			}
			return data, nil
		default:
			return nil, fmt.Errorf("unexpected peer message %q", frame.Type)
		}
	}
}

// WriteFile sends one regular file to a peer, along with the version vector
// the peer's index entry for relative must hold once the write lands. The
// peer must acknowledge the complete stream with an end marker before this
// returns successfully.
func WriteFile(ctx context.Context, endpoint Endpoint, share, relative string, data []byte, expectedHash string, manifest metadata.Manifest, vec vector.Vector) error {
	return writeFile(ctx, endpoint, messageWriteFile, share, relative, data, expectedHash, "", manifest, vec)
}

// WriteConflictFile preserves the peer's existing version under a conflict
// name before installing the winning content, along with the merged version
// vector the peer's entry must hold once it lands.
func WriteConflictFile(ctx context.Context, endpoint Endpoint, share, relative string, data []byte, expectedHash, loser string, manifest metadata.Manifest, vec vector.Vector) error {
	return writeFile(ctx, endpoint, messageWriteFile, share, relative, data, expectedHash, loser, manifest, vec)
}

// WriteConflictCopy sends a losing version without replacing the canonical
// winner on the peer. The copy lands at a new path neither side has tracked
// before, so it carries no vector: the peer's next local scan picks it up as
// an ordinary creation.
func WriteConflictCopy(ctx context.Context, endpoint Endpoint, share, relative string, data []byte, expectedHash, suffix string, manifest metadata.Manifest) error {
	return writeFile(ctx, endpoint, messageConflictCopy, share, relative, data, expectedHash, suffix, manifest, nil)
}

func writeFile(ctx context.Context, endpoint Endpoint, requestType, share, relative string, data []byte, expectedHash, loser string, manifest metadata.Manifest, vec vector.Vector) error {
	if endpoint.Address == "" || share == "" {
		return errors.New("peer address and share are required")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return err
	}
	if err := validateSHA256(expectedHash); err != nil {
		return fmt.Errorf("invalid write hash: %w", err)
	}
	if loser != "" {
		if err := peername.Validate(loser); err != nil {
			return err
		}
	}
	if !strings.EqualFold(fmt.Sprintf("%x", sha256Sum(data)), expectedHash) {
		return fmt.Errorf("local file %q hash mismatch", relative)
	}
	var request bytes.Buffer
	frames := frameWriter{w: &request}
	expectedHash = strings.ToLower(expectedHash)
	if err := frames.write(message{Type: requestType, Share: share, Path: relative, Size: int64(len(data)), Hash: expectedHash, Peer: loser, Metadata: manifest, Version: vec}); err != nil {
		return err
	}
	for offset := 0; offset < len(data); offset += fileChunkSize {
		end := offset + fileChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := frames.write(message{Type: messageChunk, Data: data[offset:end]}); err != nil {
			return err
		}
	}
	if err := frames.write(message{Type: messageEnd}); err != nil {
		return err
	}
	return runMutation(ctx, endpoint, request.Bytes(), true)
}

// ReuseFile asks the peer to satisfy a write from a matching local index
// file, along with the version vector the peer's entry must hold once
// reused. A false result means the caller must send the bytes normally.
func ReuseFile(ctx context.Context, endpoint Endpoint, share, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector) (bool, error) {
	if endpoint.Address == "" || share == "" || expectedHash == "" {
		return false, errors.New("peer address, share, and hash are required")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return false, err
	}
	if err := validateSHA256(expectedHash); err != nil {
		return false, fmt.Errorf("invalid reuse hash: %w", err)
	}
	expectedHash = strings.ToLower(expectedHash)
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageReuseFile, Share: share, Path: relative, Hash: expectedHash, Metadata: manifest, Version: vec}); err != nil {
		return false, err
	}
	output, err := runSSH(ctx, endpoint, false, request.Bytes())
	if err != nil {
		return false, err
	}
	response, err := (frameReader{r: bufio.NewReader(bytes.NewReader(output))}).read()
	if err != nil {
		return false, &Error{err: fmt.Errorf("read peer %q reuse response: %w", endpoint.Address, err)}
	}
	switch response.Type {
	case messageReused:
		return true, nil
	case messageReuseMiss:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected peer reuse response %q", response.Type)
	}
}

// DeleteFile asks a peer to move a file to its configured trash and record
// the given tombstone vector for it.
func DeleteFile(ctx context.Context, endpoint Endpoint, share, relative string, vec vector.Vector) error {
	if endpoint.Address == "" || share == "" {
		return errors.New("peer address and share are required")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageDeleteFile, Share: share, Path: relative, Version: vec}); err != nil {
		return err
	}
	return runMutation(ctx, endpoint, request.Bytes(), false)
}

// ApplyDirectory asks a peer to create or update a directory's metadata.
func ApplyDirectory(ctx context.Context, endpoint Endpoint, share, relative string, manifest metadata.Manifest) error {
	return runSimpleMutation(ctx, endpoint, message{Type: messageApplyDir, Share: share, Path: relative, Metadata: manifest})
}

// DeleteDirectory asks a peer to trash an empty directory.
func DeleteDirectory(ctx context.Context, endpoint Endpoint, share, relative string) error {
	return runSimpleMutation(ctx, endpoint, message{Type: messageDeleteDir, Share: share, Path: relative})
}

// MergeVector asks a peer to advance its index entry for relative to vec
// without moving any bytes: the resolution for a concurrent-but-identical
// pair (engine.Merge), where no mutation RPC carries the vector otherwise.
func MergeVector(ctx context.Context, endpoint Endpoint, share, relative string, vec vector.Vector) error {
	if share == "" {
		return errors.New("share name is empty")
	}
	return runSimpleMutation(ctx, endpoint, message{Type: messageMergeVector, Share: share, Path: relative, Version: vec})
}

func runSimpleMutation(ctx context.Context, endpoint Endpoint, requestMessage message) error {
	if endpoint.Address == "" || requestMessage.Share == "" {
		return errors.New("peer address and share are required")
	}
	if err := ValidateRelativePath(requestMessage.Path); err != nil {
		return err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(requestMessage); err != nil {
		return err
	}
	return runMutation(ctx, endpoint, request.Bytes(), false)
}

func runMutationResponse(ctx context.Context, endpoint Endpoint, request []byte, bulk bool) (message, error) {
	output, err := runSSH(ctx, endpoint, bulk, request)
	if err != nil {
		return message{}, err
	}
	reader := frameReader{r: bufio.NewReader(bytes.NewReader(output))}
	response, err := reader.read()
	if err != nil {
		return message{}, &Error{err: fmt.Errorf("read peer %q mutation response: %w", endpoint.Address, err)}
	}
	if response.Type != messageEnd {
		return message{}, fmt.Errorf("unexpected peer mutation response %q", response.Type)
	}
	return response, nil
}

func runMutation(ctx context.Context, endpoint Endpoint, request []byte, bulk bool) error {
	_, err := runMutationResponse(ctx, endpoint, request, bulk)
	return err
}

// Serve handles one peer request using the enabled callbacks. A nil callback
// disables its corresponding capability. A nil handshake skips the peer
// hello exchange.
func Serve(reader io.Reader, writer io.Writer, callbacks Callbacks, handshake *Handshake) error {
	requestReader := frameReader{r: bufio.NewReader(reader)}
	if handshake != nil {
		hello, err := requestReader.read()
		if err != nil {
			return err
		}
		if hello.Type != messageHello {
			return errors.New("peer hello is required")
		}
		received, err := connection.NormalizePublicKey(hello.Key)
		if err != nil {
			return fmt.Errorf("peer hello key: %w", err)
		}
		expected, err := connection.NormalizePublicKey(handshake.ExpectedPeerKey)
		if err != nil {
			return fmt.Errorf("configured peer key: %w", err)
		}
		if received != expected {
			return errors.New("peer hello key differs from configured key")
		}
		localKey, err := connection.NormalizePublicKey(handshake.LocalPublicKey)
		if err != nil {
			return fmt.Errorf("local public key: %w", err)
		}
		if err := (frameWriter{w: writer}).write(message{Type: messageHelloReply, Key: localKey}); err != nil {
			return err
		}
	}
	request, err := requestReader.read()
	if err != nil {
		return err
	}
	switch request.Type {
	case messagePing:
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	case messageRequestCycle:
		if callbacks.RequestCycle == nil {
			return errors.New("cycle request is not configured")
		}
		if request.Share == "" {
			return errors.New("share name is empty")
		}
		actions, err := callbacks.RequestCycle(request.Share)
		if err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd, Actions: actions})
	case messageBindShare:
		if callbacks.BindShare == nil {
			return errors.New("share binding is not configured")
		}
		if request.Share == "" {
			return errors.New("share name is empty")
		}
		created, err := callbacks.BindShare(request.Share)
		if err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd, Created: created})
	case messageUnbindShare:
		if callbacks.UnbindShare == nil {
			return errors.New("share unbinding is not configured")
		}
		if request.Share == "" {
			return errors.New("share name is empty")
		}
		if err := callbacks.UnbindShare(request.Share); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	case messageListShares:
		if callbacks.ListShares == nil {
			return errors.New("share discovery is not configured")
		}
		shares, err := callbacks.ListShares()
		if err != nil {
			return err
		}
		ordered := append([]string(nil), shares...)
		sort.Strings(ordered)
		responseWriter := frameWriter{w: writer}
		for _, share := range ordered {
			if share == "" {
				return errors.New("cannot serve an empty share name")
			}
			if err := responseWriter.write(message{Type: messageShare, Share: share}); err != nil {
				return err
			}
		}
		return responseWriter.write(message{Type: messageEnd})
	case messageListFiles:
		if callbacks.ListFiles == nil {
			return errors.New("file listing is not configured")
		}
		files, id, err := callbacks.ListFiles(request.Share, request.Id)
		if err != nil {
			return err
		}
		return writeFiles(writer, request.Share, id, files)
	case messageConflictCheck:
		if callbacks.ConflictCopyExists == nil {
			return errors.New("conflict collision check is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		exists, err := callbacks.ConflictCopyExists(request.Share, request.Path, request.Peer)
		if err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd, Exists: exists})
	case messageReadFile:
		if callbacks.ReadFile == nil {
			return errors.New("file reader is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		file, err := callbacks.ReadFile(request.Share, request.Path)
		if err != nil {
			return err
		}
		defer file.Close()
		responseWriter := frameWriter{w: writer}
		buffer := make([]byte, fileChunkSize)
		for {
			count, readErr := file.Read(buffer)
			if count > 0 {
				data := append([]byte(nil), buffer[:count]...)
				if err := responseWriter.write(message{Type: messageChunk, Data: data}); err != nil {
					return err
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return responseWriter.write(message{Type: messageEnd})
				}
				return fmt.Errorf("read peer file: %w", readErr)
			}
		}
	case messageWriteFile:
		if callbacks.WriteFile == nil {
			return errors.New("file writer is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if request.Size < 0 {
			return fmt.Errorf("invalid declared write size %d", request.Size)
		}
		if err := validateSHA256(request.Hash); err != nil {
			return fmt.Errorf("invalid write hash: %w", err)
		}
		if request.Peer != "" {
			if err := peername.Validate(request.Peer); err != nil {
				return err
			}
		}
		if request.Peer != "" && callbacks.WriteConflict == nil {
			return errors.New("conflict writer is not configured")
		}
		return readAndWriteFile(requestReader, writer, request.Share, request.Path, request.Peer, strings.ToLower(request.Hash), request.Size, request.Metadata, request.Version, callbacks.WriteFile, callbacks.WriteConflict)
	case messageConflictCopy:
		if callbacks.WriteConflictCopy == nil {
			return errors.New("conflict copy writer is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if request.Size < 0 {
			return fmt.Errorf("invalid declared write size %d", request.Size)
		}
		if err := validateSHA256(request.Hash); err != nil {
			return fmt.Errorf("invalid conflict copy hash: %w", err)
		}
		if err := peername.Validate(request.Peer); err != nil {
			return err
		}
		conflictCopyWriter := func(share, relative, suffix, expectedHash string, manifest metadata.Manifest, _ vector.Vector, contents io.Reader) error {
			return callbacks.WriteConflictCopy(share, relative, suffix, expectedHash, manifest, contents)
		}
		return readAndWriteFile(requestReader, writer, request.Share, request.Path, request.Peer, strings.ToLower(request.Hash), request.Size, request.Metadata, nil, nil, conflictCopyWriter)
	case messageMergeVector:
		if callbacks.MergeVector == nil {
			return errors.New("vector merge is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if err := callbacks.MergeVector(request.Share, request.Path, request.Version); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	case messageReuseFile:
		if callbacks.ReuseFile == nil {
			return errors.New("file reuse is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if err := validateSHA256(request.Hash); err != nil {
			return fmt.Errorf("invalid reuse hash: %w", err)
		}
		reused, err := callbacks.ReuseFile(request.Share, request.Path, strings.ToLower(request.Hash), request.Metadata, request.Version)
		if err != nil {
			return err
		}
		response := messageReuseMiss
		if reused {
			response = messageReused
		}
		return (frameWriter{w: writer}).write(message{Type: response})
	case messageDeleteFile:
		if callbacks.DeleteFile == nil {
			return errors.New("file deleter is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if err := callbacks.DeleteFile(request.Share, request.Path, request.Version); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	case messageApplyDir:
		if callbacks.ApplyDirectory == nil {
			return errors.New("directory writer is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if err := callbacks.ApplyDirectory(request.Share, request.Path, request.Metadata); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	case messageDeleteDir:
		if callbacks.DeleteDirectory == nil {
			return errors.New("directory deleter is not configured")
		}
		if err := ValidateRelativePath(request.Path); err != nil {
			return err
		}
		if err := callbacks.DeleteDirectory(request.Share, request.Path); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	default:
		return fmt.Errorf("unexpected peer request %q", request.Type)
	}
}

func readAndWriteFile(reader frameReader, writer io.Writer, share, relative, loser, expectedHash string, declaredSize int64, manifest metadata.Manifest, vec vector.Vector,
	fileWriter func(share, relative, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error,
	conflictWriter func(share, relative, loser, expectedHash string, manifest metadata.Manifest, vec vector.Vector, contents io.Reader) error) error {
	contents, err := os.CreateTemp("", ".l2sync-receive-*")
	if err != nil {
		return fmt.Errorf("create receive buffer: %w", err)
	}
	defer os.Remove(contents.Name())
	defer contents.Close()
	var received int64
	for {
		frame, err := reader.read()
		if err != nil {
			return err
		}
		switch frame.Type {
		case messageChunk:
			if len(frame.Data) == 0 {
				return errors.New("peer returned an empty file chunk")
			}
			chunkSize := int64(len(frame.Data))
			if chunkSize > declaredSize-received {
				return fmt.Errorf("received content beyond declared size %d", declaredSize)
			}
			received += chunkSize
			if _, err := contents.Write(frame.Data); err != nil {
				return err
			}
		case messageEnd:
			if received != declaredSize {
				return fmt.Errorf("received %d bytes, expected %d", received, declaredSize)
			}
			if _, err := contents.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("rewind receive buffer: %w", err)
			}
			var writeErr error
			if loser != "" {
				writeErr = conflictWriter(share, relative, loser, expectedHash, manifest, vec, contents)
			} else {
				writeErr = fileWriter(share, relative, expectedHash, manifest, vec, contents)
			}
			if writeErr != nil {
				return writeErr
			}
			return (frameWriter{w: writer}).write(message{Type: messageEnd})
		default:
			return fmt.Errorf("unexpected peer mutation frame %q", frame.Type)
		}
	}
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func writeFiles(writer io.Writer, share, id string, files []PeerFile) error {
	if share == "" {
		return errors.New("cannot serve an empty share name")
	}
	ordered := append([]PeerFile(nil), files...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Path < ordered[right].Path })
	responseWriter := frameWriter{w: writer}
	seen := make(map[string]bool)
	for _, file := range ordered {
		if err := ValidateRelativePath(file.Path); err != nil {
			return err
		}
		if file.Size < 0 {
			return fmt.Errorf("invalid peer file %q", file.Path)
		}
		if err := validateListingEntry(file.Path, file.Hash, file.Directory, file.Deleted, seen); err != nil {
			return err
		}
		if err := responseWriter.write(message{
			Type: messageFile, Path: file.Path, Size: file.Size, Hash: strings.ToLower(file.Hash), Metadata: file.Metadata,
			Directory: file.Directory, Deleted: file.Deleted, DeletedAt: file.DeletedAt, Version: file.Version,
		}); err != nil {
			return err
		}
	}
	return responseWriter.write(message{Type: messageEnd, Id: id})
}

func validateSHA256(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("SHA-256 hash must contain %d hexadecimal characters", sha256.Size*2)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("SHA-256 hash contains non-hexadecimal characters")
	}
	return nil
}

// validateListingEntry validates one listing entry. A tombstone (deleted
// true) carries no content, so it is exempt from the hash check that every
// other non-directory entry requires (concept.md 4.2).
func validateListingEntry(value, hash string, directory, deleted bool, seen map[string]bool) error {
	if _, exists := seen[value]; exists {
		return fmt.Errorf("duplicate peer listing path %q", value)
	}
	for ancestor := path.Dir(value); ancestor != "."; ancestor = path.Dir(ancestor) {
		if ancestorDirectory, exists := seen[ancestor]; exists && !ancestorDirectory {
			return fmt.Errorf("peer listing path %q descends from file %q", value, ancestor)
		}
	}
	if directory {
		if hash != "" {
			return fmt.Errorf("peer directory %q has a content hash", value)
		}
		if deleted {
			return fmt.Errorf("peer directory %q cannot be a tombstone", value)
		}
		seen[value] = true
		return nil
	}
	prefix := value + "/"
	for existing := range seen {
		if strings.HasPrefix(existing, prefix) {
			return fmt.Errorf("peer listing file %q collides with descendant %q", value, existing)
		}
	}
	if deleted {
		if hash != "" {
			return fmt.Errorf("peer tombstone %q has a content hash", value)
		}
	} else if err := validateSHA256(hash); err != nil {
		return fmt.Errorf("invalid hash for peer file %q: %w", value, err)
	}
	seen[value] = false
	return nil
}

// ValidateRelativePath rejects peer-supplied paths that are empty, absolute,
// non-canonical, or able to escape the share root.
func ValidateRelativePath(value string) error {
	if err := sharepath.Validate(value); err != nil {
		return fmt.Errorf("invalid peer file path %q", value)
	}
	return nil
}

func runSSH(ctx context.Context, endpoint Endpoint, bulk bool, input []byte) ([]byte, error) {
	if endpoint.Name == "" || endpoint.Address == "" || endpoint.LocalPublicKey == "" || endpoint.PrivateKey == "" || endpoint.AuthorizedKeys == "" {
		return nil, errors.New("complete pinned peer endpoint is required")
	}
	command, cleanup, err := sshProcess(ctx, endpoint.Address, endpoint.PrivateKey, bulk)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	var wire bytes.Buffer
	if err := (frameWriter{w: &wire}).write(message{Type: messageHello, Key: endpoint.LocalPublicKey}); err != nil {
		return nil, err
	}
	if _, err := wire.Write(input); err != nil {
		return nil, err
	}
	command.Stdin = &wire
	stderr := boundedBuffer{limit: sshStderrLimit}
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, classifySSHFailure(endpoint.Address, err, ctx.Err(), stderr.Bytes())
	}
	reader := bufio.NewReader(bytes.NewReader(output))
	reply, err := (frameReader{r: reader}).read()
	if err != nil {
		return nil, &Error{err: fmt.Errorf("read peer %q hello: %w", endpoint.Address, err)}
	}
	if reply.Type != messageHelloReply {
		return nil, fmt.Errorf("peer %q returned %q before hello reply", endpoint.Address, reply.Type)
	}
	received, err := connection.NormalizePublicKey(reply.Key)
	if err != nil {
		return nil, fmt.Errorf("peer %q returned invalid public key: %w", endpoint.Address, err)
	}
	localKey, err := connection.NormalizePublicKey(endpoint.LocalPublicKey)
	if err != nil {
		return nil, fmt.Errorf("local installation key: %w", err)
	}
	if received == localKey {
		return nil, fmt.Errorf("peer %q uses this installation's public key", endpoint.Name)
	}
	if endpoint.PublicKey != "" {
		expected, err := connection.NormalizePublicKey(endpoint.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer %q configured public key: %w", endpoint.Name, err)
		}
		if received != expected {
			return nil, fmt.Errorf("peer %q public key differs from configured key", endpoint.Name)
		}
	} else if endpoint.AcceptPublicKey == nil {
		return nil, fmt.Errorf("peer %q has no pinned public key", endpoint.Name)
	}
	if endpoint.AcceptPublicKey != nil {
		if err := endpoint.AcceptPublicKey(received); err != nil {
			return nil, fmt.Errorf("accept peer %q public key: %w", endpoint.Name, err)
		}
	}
	if err := connection.AddGrant(endpoint.AuthorizedKeys, endpoint.Name, received); err != nil {
		return nil, fmt.Errorf("install reciprocal grant for peer %q: %w", endpoint.Name, err)
	}
	return io.ReadAll(reader)
}

func classifySSHFailure(address string, commandErr, contextErr error, stderr []byte) error {
	if contextErr != nil {
		return &Error{err: fmt.Errorf("connect to peer %q: %w", address, contextErr)}
	}
	var exitErr *exec.ExitError
	if errors.As(commandErr, &exitErr) && exitErr.ExitCode() != 255 {
		if exitErr.ExitCode() == remoteLockedExitCode {
			return fmt.Errorf("peer %q mutation lock unavailable: %w", address, lock.ErrTimeout)
		}
		if detail := sanitizeSSHStderr(stderr); detail != "" {
			return fmt.Errorf("peer %q rejected request: %s", address, detail)
		}
		return fmt.Errorf("peer %q rejected request: %w", address, commandErr)
	}
	detail := sanitizeSSHStderr(stderr)
	auth := strings.Contains(detail, "Permission denied")
	if detail != "" {
		return &Error{err: fmt.Errorf("connect to peer %q: %w: %s", address, commandErr, detail), auth: auth}
	}
	return &Error{err: fmt.Errorf("connect to peer %q: %w", address, commandErr), auth: auth}
}

func sshProcess(ctx context.Context, address, privateKey string, bulk bool) (*exec.Cmd, func(), error) {
	if err := config.ValidatePeerAddress(address); err != nil {
		return nil, nil, fmt.Errorf("invalid SSH destination: %w", err)
	}
	configPath, cleanup, err := sanitizedSSHConfig(ctx, address)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare dedicated-key SSH configuration: %w", err)
	}
	controlPath := ""
	if !bulk {
		controlPath = safeControlSocketPath()
	}
	return exec.CommandContext(ctx, sshCommand, sshArguments(configPath, controlPath, privateKey, bulk)...), cleanup, nil
}

func sshArguments(configPath, controlPath, privateKey string, bulk bool) []string {
	controlMaster := "auto"
	if bulk || controlPath == "" {
		controlPath = "none"
		controlMaster = "no"
	}
	return []string{
		"-F", configPath,
		"-T",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PreferredAuthentications=publickey",
		"-i", privateKey,
		"-o", "ControlMaster=" + controlMaster,
		"-o", "ControlPersist=" + sshControlPersist,
		"-o", "ControlPath=" + controlPath,
		sshConfigHost, remoteBinary, "serve",
	}
}

func sanitizedSSHConfig(ctx context.Context, address string) (string, func(), error) {
	command := exec.CommandContext(ctx, sshCommand, "-G", address)
	var output boundedBuffer
	output.limit = sshConfigLimit
	var stderr boundedBuffer
	stderr.limit = sshStderrLimit
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", nil, fmt.Errorf("resolve SSH alias %q: %w: %s", address, err, sanitizeSSHStderr(stderr.Bytes()))
	}
	if output.overflow {
		return "", nil, fmt.Errorf("resolved SSH configuration exceeds %d bytes", sshConfigLimit)
	}
	contents, err := sanitizeEffectiveSSHConfig(output.contents)
	if err != nil {
		return "", nil, err
	}
	parent := os.TempDir()
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" && filepath.IsAbs(runtimeDir) && validatePrivateDirectory(runtimeDir) == nil {
		parent = runtimeDir
	}
	file, err := os.CreateTemp(parent, sshConfigPrefix)
	if err != nil {
		return "", nil, fmt.Errorf("create temporary SSH configuration: %w", err)
	}
	name := file.Name()
	cleanup := func() { _ = os.Remove(name) }
	fail := func(cause error) (string, func(), error) {
		_ = file.Close()
		cleanup()
		return "", nil, cause
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("protect temporary SSH configuration: %w", err))
	}
	if _, err := file.Write(contents); err != nil {
		return fail(fmt.Errorf("write temporary SSH configuration: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync temporary SSH configuration: %w", err))
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close temporary SSH configuration: %w", err)
	}
	return name, cleanup, nil
}

var allowedSSHOptions = map[string]bool{
	"hostname":  true,
	"port":      true,
	"user":      true,
	"proxyjump": true,
}

func sanitizeEffectiveSSHConfig(effective []byte) ([]byte, error) {
	var result bytes.Buffer
	result.WriteString("Host " + sshConfigHost + "\n")
	scanner := bufio.NewScanner(bytes.NewReader(effective))
	scanner.Buffer(make([]byte, 4096), sshConfigLimit)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, " ")
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("cannot represent resolved SSH option %q", line)
		}
		if !allowedSSHOptions[key] {
			continue
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid resolved SSH option %q", key)
		}
		fmt.Fprintf(&result, "  %s %s\n", key, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse resolved SSH configuration: %w", err)
	}
	return result.Bytes(), nil
}

func safeControlSocketPath() string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" || !filepath.IsAbs(runtimeDir) || validatePrivateDirectory(runtimeDir) != nil {
		return ""
	}
	candidate := filepath.Join(runtimeDir, "l2s-%C")
	if len(candidate)-len("%C")+controlHashLength > unixSocketPathLimit {
		return ""
	}
	return candidate
}

func validatePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("directory is not private to the current user")
	}
	return nil
}

type boundedBuffer struct {
	contents []byte
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := max(buffer.limit-len(buffer.contents), 0)
	if len(value) > remaining {
		value = value[:remaining]
		buffer.overflow = true
	}
	buffer.contents = append(buffer.contents, value...)
	return written, nil
}

func (buffer *boundedBuffer) Bytes() []byte { return buffer.contents }

func sanitizeSSHStderr(value []byte) string {
	clean := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, string(value))
	clean = strings.Join(strings.Fields(clean), " ")
	if index := strings.Index(clean, "ssh-ed25519"); index >= 0 {
		clean = strings.TrimSpace(clean[:index]) + " [redacted key material]"
		clean = strings.TrimSpace(clean)
	}
	runes := []rune(clean)
	if len(runes) > sshStderrExcerpt {
		clean = string(runes[:sshStderrExcerpt]) + "…"
	}
	return clean
}

// Exchange performs the pinned hello exchange without filesystem access.
func Exchange(ctx context.Context, endpoint Endpoint) error {
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messagePing}); err != nil {
		return err
	}
	return runMutation(ctx, endpoint, request.Bytes(), false)
}

// RequestCycle asks the deterministic initiator to synchronously reconcile one
// exact bound folder. The caller holds no mutation lock while waiting.
func RequestCycle(ctx context.Context, endpoint Endpoint, share string) (int, error) {
	if share == "" {
		return 0, errors.New("share name is empty")
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageRequestCycle, Share: share}); err != nil {
		return 0, err
	}
	response, err := runMutationResponse(ctx, endpoint, request.Bytes(), false)
	return response.Actions, err
}

// BindShare asks the authenticated offerer to bind share to this peer.
func BindShare(ctx context.Context, endpoint Endpoint, share string) (bool, error) {
	if share == "" {
		return false, errors.New("share name is empty")
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageBindShare, Share: share}); err != nil {
		return false, err
	}
	response, err := runMutationResponse(ctx, endpoint, request.Bytes(), false)
	return response.Created, err
}

// ConflictCopyExists checks the exact deterministic artifact name before
// either replica begins a conflict transaction.
func ConflictCopyExists(ctx context.Context, endpoint Endpoint, share, relative, suffix string) (bool, error) {
	if share == "" {
		return false, errors.New("share name is empty")
	}
	if err := ValidateRelativePath(relative); err != nil {
		return false, err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageConflictCheck, Share: share, Path: relative, Peer: suffix}); err != nil {
		return false, err
	}
	response, err := runMutationResponse(ctx, endpoint, request.Bytes(), false)
	return response.Exists, err
}

// UnbindShare compensates a failed join transaction. The server removes only
// a binding owned by the authenticated peer.
func UnbindShare(ctx context.Context, endpoint Endpoint, share string) error {
	if share == "" {
		return errors.New("share name is empty")
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageUnbindShare, Share: share}); err != nil {
		return err
	}
	return runMutation(ctx, endpoint, request.Bytes(), false)
}
