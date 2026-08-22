//go:build linux

package transport

import (
	"bytes"
	"errors"
	"testing"
)

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
	if err := (frameWriter{w: &stream}).write(message{Type: messageFile, Path: "a.txt", Size: 1}); err != nil {
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
	files := []PeerFile{{Path: "z.txt", Size: 3}, {Path: "a.txt", Size: 1}}
	err := ServePeer(&request, &response, []string{"notes"}, func(share string) ([]PeerFile, error) {
		if share != "notes" {
			t.Fatalf("file lister share = %q, want notes", share)
		}
		return files, nil
	})
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
	err := ServePeer(&request, &response, []string{"notes"}, func(share string) ([]PeerFile, error) {
		if share != "notes" {
			t.Fatalf("file lister share = %q, want notes", share)
		}
		return []PeerFile{{Path: "notes/a.txt", Size: 4}}, nil
	})
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

func TestReadFilesRejectsUnsafePath(t *testing.T) {
	var stream bytes.Buffer
	if err := (frameWriter{w: &stream}).write(message{Type: messageFile, Path: "../outside", Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFiles(&stream); err == nil {
		t.Fatal("readFiles error = nil, want unsafe path error")
	}
}
