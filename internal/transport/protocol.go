//go:build linux

// Package transport contains the peer wire protocol and its SSH adapter.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"sort"
	"strings"
)

const (
	frameHeaderSize = 4
	maxFrameSize    = 16 << 20

	messageListShares = "list-shares"
	messageListFiles  = "list-files"
	messageReadFile   = "read-file"
	messageWriteFile  = "write-file"
	messageDeleteFile = "delete-file"
	messageShare      = "share"
	messageFile       = "file"
	messageEnd        = "end"
	messageChunk      = "chunk"
	sshCommand        = "ssh"
	remoteBinary      = "l2sync"
	fileChunkSize     = 1 << 20
)

var errUnexpectedEnd = errors.New("peer listing ended without an end-of-stream marker")

type message struct {
	Type  string `json:"type"`
	Share string `json:"share,omitempty"`
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
	Hash  string `json:"hash,omitempty"`
	Data  []byte `json:"data,omitempty"`
	Peer  string `json:"peer,omitempty"`
}

// PeerFile is one regular file reported by a peer listing.
type PeerFile struct {
	Path string
	Size int64
	Hash string
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

func writeListFilesRequest(writer io.Writer, share string) error {
	if share == "" {
		return errors.New("share name is empty")
	}
	return (frameWriter{w: writer}).write(message{Type: messageListFiles, Share: share})
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

func readFiles(reader io.Reader) ([]PeerFile, error) {
	frames := frameReader{r: bufio.NewReader(reader)}
	files := make([]PeerFile, 0)
	for {
		message, err := frames.read()
		if err != nil {
			return nil, err
		}
		switch message.Type {
		case messageFile:
			if message.Path == "" {
				return nil, errors.New("peer returned an empty file path")
			}
			if err := validateRelativePath(message.Path); err != nil {
				return nil, err
			}
			if message.Size < 0 {
				return nil, fmt.Errorf("peer returned a negative file size for %q", message.Path)
			}
			if message.Hash == "" {
				return nil, fmt.Errorf("peer returned an empty hash for %q", message.Path)
			}
			files = append(files, PeerFile{Path: message.Path, Size: message.Size, Hash: message.Hash})
		case messageEnd:
			return files, nil
		default:
			return nil, fmt.Errorf("unexpected peer message %q", message.Type)
		}
	}
}

// ListShares asks a peer for its locally offered shares over SSH.
func ListShares(ctx context.Context, address string) ([]string, error) {
	if address == "" {
		return nil, errors.New("peer address is empty")
	}
	var request bytes.Buffer
	if err := writeListSharesRequest(&request); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, sshCommand, address, remoteBinary, "serve")
	command.Stdin = bytes.NewReader(request.Bytes())
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("connect to peer %q: %w", address, err)
	}
	return readShares(bytes.NewReader(output))
}

// ListFiles asks a peer for the regular files in one offered share.
func ListFiles(ctx context.Context, address, share string) ([]PeerFile, error) {
	if address == "" {
		return nil, errors.New("peer address is empty")
	}
	var request bytes.Buffer
	if err := writeListFilesRequest(&request, share); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, sshCommand, address, remoteBinary, "serve")
	command.Stdin = bytes.NewReader(request.Bytes())
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("connect to peer %q: %w", address, err)
	}
	return readFiles(bytes.NewReader(output))
}

// ReadFile retrieves one regular file from a peer after validating its path
// and hash. The response must terminate with an explicit end marker.
func ReadFile(ctx context.Context, address, share, relative, expectedHash string) ([]byte, error) {
	if address == "" || share == "" {
		return nil, errors.New("peer address and share are required")
	}
	if err := validateRelativePath(relative); err != nil {
		return nil, err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageReadFile, Share: share, Path: relative}); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, sshCommand, address, remoteBinary, "serve")
	command.Stdin = bytes.NewReader(request.Bytes())
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("connect to peer %q: %w", address, err)
	}
	reader := frameReader{r: bufio.NewReader(bytes.NewReader(output))}
	var contents bytes.Buffer
	for {
		frame, err := reader.read()
		if err != nil {
			return nil, err
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
			if expectedHash != "" && fmt.Sprintf("%x", sha256Sum(data)) != expectedHash {
				return nil, fmt.Errorf("peer file %q hash mismatch", relative)
			}
			return data, nil
		default:
			return nil, fmt.Errorf("unexpected peer message %q", frame.Type)
		}
	}
}

// WriteFile sends one regular file to a peer. The peer must acknowledge the
// complete stream with an end marker before this returns successfully.
func WriteFile(ctx context.Context, address, share, relative string, data []byte, expectedHash string) error {
	return writeFile(ctx, address, share, relative, data, expectedHash, "")
}

// WriteConflictFile preserves the peer's existing version under a conflict
// name before installing the winning content.
func WriteConflictFile(ctx context.Context, address, share, relative string, data []byte, expectedHash, loser string) error {
	return writeFile(ctx, address, share, relative, data, expectedHash, loser)
}

func writeFile(ctx context.Context, address, share, relative string, data []byte, expectedHash, loser string) error {
	if address == "" || share == "" {
		return errors.New("peer address and share are required")
	}
	if err := validateRelativePath(relative); err != nil {
		return err
	}
	if expectedHash != "" && fmt.Sprintf("%x", sha256Sum(data)) != expectedHash {
		return fmt.Errorf("local file %q hash mismatch", relative)
	}
	var request bytes.Buffer
	frames := frameWriter{w: &request}
	if err := frames.write(message{Type: messageWriteFile, Share: share, Path: relative, Peer: loser}); err != nil {
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
	return runMutation(ctx, address, request.Bytes())
}

// DeleteFile asks a peer to move a file to its configured trash.
func DeleteFile(ctx context.Context, address, share, relative string) error {
	if address == "" || share == "" {
		return errors.New("peer address and share are required")
	}
	if err := validateRelativePath(relative); err != nil {
		return err
	}
	var request bytes.Buffer
	if err := (frameWriter{w: &request}).write(message{Type: messageDeleteFile, Share: share, Path: relative}); err != nil {
		return err
	}
	return runMutation(ctx, address, request.Bytes())
}

func runMutation(ctx context.Context, address string, request []byte) error {
	command := exec.CommandContext(ctx, sshCommand, address, remoteBinary, "serve")
	command.Stdin = bytes.NewReader(request)
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("connect to peer %q: %w", address, err)
	}
	reader := frameReader{r: bufio.NewReader(bytes.NewReader(output))}
	response, err := reader.read()
	if err != nil {
		return err
	}
	if response.Type != messageEnd {
		return fmt.Errorf("unexpected peer mutation response %q", response.Type)
	}
	return nil
}

// ServePeer handles one discovery request. The fileLister is called only for
// a requested share after the request has been validated.
func ServePeer(reader io.Reader, writer io.Writer, shares []string, fileLister func(string) ([]PeerFile, error)) error {
	return ServePeerWithMutations(reader, writer, shares, fileLister, nil, nil, nil)
}

// ServePeerWithReader is ServePeer with an optional regular-file reader.
func ServePeerWithReader(reader io.Reader, writer io.Writer, shares []string, fileLister func(string) ([]PeerFile, error), fileReader func(string, string) (io.ReadCloser, error)) error {
	return ServePeerWithMutations(reader, writer, shares, fileLister, fileReader, nil, nil)
}

// ServePeerWithMutations handles discovery, reads, writes, and deletes. A nil
// callback disables that operation.
func ServePeerWithMutations(reader io.Reader, writer io.Writer, shares []string, fileLister func(string) ([]PeerFile, error), fileReader func(string, string) (io.ReadCloser, error), fileWriter func(string, string, io.Reader) error, fileDeleter func(string, string) error) error {
	return servePeerWithMutations(reader, writer, shares, fileLister, fileReader, fileWriter, fileDeleter, nil)
}

// ServePeerWithConflict adds a callback for writes that must preserve the
// existing remote version as a conflict file.
func ServePeerWithConflict(reader io.Reader, writer io.Writer, shares []string, fileLister func(string) ([]PeerFile, error), fileReader func(string, string) (io.ReadCloser, error), fileWriter func(string, string, io.Reader) error, fileDeleter func(string, string) error, conflictWriter func(string, string, string, io.Reader) error) error {
	return servePeerWithMutations(reader, writer, shares, fileLister, fileReader, fileWriter, fileDeleter, conflictWriter)
}

func servePeerWithMutations(reader io.Reader, writer io.Writer, shares []string, fileLister func(string) ([]PeerFile, error), fileReader func(string, string) (io.ReadCloser, error), fileWriter func(string, string, io.Reader) error, fileDeleter func(string, string) error, conflictWriter func(string, string, string, io.Reader) error) error {
	requestReader := frameReader{r: bufio.NewReader(reader)}
	request, err := requestReader.read()
	if err != nil {
		return err
	}
	switch request.Type {
	case messageListShares:
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
		if fileLister == nil {
			return errors.New("file listing is not configured")
		}
		files, err := fileLister(request.Share)
		if err != nil {
			return err
		}
		return writeFiles(writer, request.Share, files)
	case messageReadFile:
		if fileReader == nil {
			return errors.New("file reader is not configured")
		}
		if err := validateRelativePath(request.Path); err != nil {
			return err
		}
		file, err := fileReader(request.Share, request.Path)
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
		if fileWriter == nil {
			return errors.New("file writer is not configured")
		}
		if err := validateRelativePath(request.Path); err != nil {
			return err
		}
		if request.Peer != "" && conflictWriter == nil {
			return errors.New("conflict writer is not configured")
		}
		return readAndWriteFile(requestReader, writer, request.Share, request.Path, request.Peer, fileWriter, conflictWriter)
	case messageDeleteFile:
		if fileDeleter == nil {
			return errors.New("file deleter is not configured")
		}
		if err := validateRelativePath(request.Path); err != nil {
			return err
		}
		if err := fileDeleter(request.Share, request.Path); err != nil {
			return err
		}
		return (frameWriter{w: writer}).write(message{Type: messageEnd})
	default:
		return fmt.Errorf("unexpected peer request %q", request.Type)
	}
}

func readAndWriteFile(reader frameReader, writer io.Writer, share, relative, loser string, fileWriter func(string, string, io.Reader) error, conflictWriter func(string, string, string, io.Reader) error) error {
	var contents bytes.Buffer
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
			if _, err := contents.Write(frame.Data); err != nil {
				return err
			}
		case messageEnd:
			var writeErr error
			if loser != "" {
				writeErr = conflictWriter(share, relative, loser, bytes.NewReader(contents.Bytes()))
			} else {
				writeErr = fileWriter(share, relative, bytes.NewReader(contents.Bytes()))
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

func writeFiles(writer io.Writer, share string, files []PeerFile) error {
	if share == "" {
		return errors.New("cannot serve an empty share name")
	}
	ordered := append([]PeerFile(nil), files...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Path < ordered[right].Path })
	responseWriter := frameWriter{w: writer}
	for _, file := range ordered {
		if err := validateRelativePath(file.Path); err != nil {
			return err
		}
		if file.Size < 0 || file.Hash == "" {
			return fmt.Errorf("invalid peer file %q", file.Path)
		}
		if err := responseWriter.write(message{Type: messageFile, Path: file.Path, Size: file.Size, Hash: file.Hash}); err != nil {
			return err
		}
	}
	return responseWriter.write(message{Type: messageEnd})
}

func validateRelativePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("invalid peer file path %q", value)
	}
	return nil
}
