//go:build linux

// Package transport contains the peer wire protocol and its SSH adapter.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
)

const (
	frameHeaderSize = 4
	maxFrameSize    = 16 << 20

	messageListShares = "list-shares"
	messageListFiles  = "list-files"
	messageShare      = "share"
	messageFile       = "file"
	messageEnd        = "end"
	sshCommand        = "ssh"
	remoteBinary      = "l2sync"
)

var errUnexpectedEnd = errors.New("peer listing ended without an end-of-stream marker")

type message struct {
	Type  string `json:"type"`
	Share string `json:"share,omitempty"`
	Path  string `json:"path,omitempty"`
	Size  int64  `json:"size,omitempty"`
}

// PeerFile is one regular file reported by a peer listing.
type PeerFile struct {
	Path string
	Size int64
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
			if message.Size < 0 {
				return nil, fmt.Errorf("peer returned a negative file size for %q", message.Path)
			}
			files = append(files, PeerFile{Path: message.Path, Size: message.Size})
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

// ServeShares handles one peer discovery request and writes a complete response.
// It is intended to be called by the remote `l2sync serve` command.
func ServeShares(reader io.Reader, writer io.Writer, shares []string) error {
	requestReader := frameReader{r: bufio.NewReader(reader)}
	request, err := requestReader.read()
	if err != nil {
		return err
	}
	if request.Type != messageListShares {
		return fmt.Errorf("unexpected peer request %q", request.Type)
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
}

// ServeFiles handles one file-list request. The caller supplies the already
// guarded file paths; this transport layer does not walk a filesystem.
func ServeFiles(reader io.Reader, writer io.Writer, share string, files []PeerFile) error {
	requestReader := frameReader{r: bufio.NewReader(reader)}
	request, err := requestReader.read()
	if err != nil {
		return err
	}
	if request.Type != messageListFiles || request.Share != share {
		return fmt.Errorf("unexpected file-list request for share %q", request.Share)
	}

	ordered := append([]PeerFile(nil), files...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Path < ordered[right].Path })
	responseWriter := frameWriter{w: writer}
	for _, file := range ordered {
		if file.Path == "" || file.Size < 0 {
			return fmt.Errorf("invalid peer file %q", file.Path)
		}
		if err := responseWriter.write(message{Type: messageFile, Path: file.Path, Size: file.Size}); err != nil {
			return err
		}
	}
	return responseWriter.write(message{Type: messageEnd})
}
