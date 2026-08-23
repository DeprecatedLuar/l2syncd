//go:build linux

package apply

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"l2syncd/internal/metadata"
)

func TestWriteIsAtomicAndReplacesRecoverably(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	path := filepath.Join(root, "nested", "note.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, "nested/note.txt", bytes.NewBufferString("new"), ""); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("contents = %q, want new", contents)
	}
	trashRoot := filepath.Join(root, ".l2sync-trash")
	if _, err := os.Stat(trashRoot); err != nil {
		t.Fatalf("trash root = %v", err)
	}
}

func TestWritePreservesBytesModeMtimeXattrsAndACL(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	payload := []byte("Exif\x00XMP\x00IPTC\x00image-bytes")
	if err := os.WriteFile(source, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(1_700_000_000, 123_456_789)
	if err := os.Chtimes(source, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(source, "user.l2sync-test", []byte("value"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skip("test filesystem lacks xattr support")
		}
		t.Fatal(err)
	}
	acl := testACL(uint32(os.Getuid()) + 10000)
	aclSupported := true
	if err := unix.Setxattr(source, "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL) {
			aclSupported = false
		} else {
			t.Fatal(err)
		}
	}
	manifest, err := metadata.Capture(source, true)
	if err != nil {
		t.Fatal(err)
	}
	if aclSupported && len(manifest.ACLAccess) == 0 {
		t.Fatal("captured ACL is empty")
	}
	destination := "nested/image.jpg"
	if err := WriteWithMetadata(root, destination, bytes.NewReader(payload), hashBytes(payload), manifest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(destination)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("bytes = %q, want exact fixture", got)
	}
}

func TestMetadataFailureLeavesExistingTargetUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0), ACLAccess: []byte{1}}
	if err := WriteWithMetadata(root, "file", bytes.NewBufferString("new"), hashBytes([]byte("new")), manifest); err == nil {
		t.Fatal("WriteWithMetadata error = nil for invalid ACL")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("target = %q, want unchanged old bytes", got)
	}
}

func TestConflictMetadataFailureLeavesCanonicalTargetUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("loser"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0), ACLAccess: []byte{1}}
	err := WriteConflictWinnerWithMetadata(root, "file", "peer", bytes.NewBufferString("winner"), hashBytes([]byte("winner")), manifest)
	if err == nil {
		t.Fatal("WriteConflictWinnerWithMetadata error = nil for invalid ACL")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "loser" {
		t.Fatalf("canonical target = %q, want unchanged loser", got)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, "*.l2sync-conflict-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("conflict files = %v, want none before validated winner", matches)
	}
}

func TestReuseRejectsStaleBaselineSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "old"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0)}
	err := Reuse(root, "new", "old", hashBytes([]byte("baseline")), manifest)
	if !errors.Is(err, ErrReuseMismatch) {
		t.Fatalf("Reuse error = %v, want ErrReuseMismatch", err)
	}
	if _, err := os.Stat(filepath.Join(root, "new")); !os.IsNotExist(err) {
		t.Fatalf("new target stat = %v, want absent", err)
	}
}

func TestReuseCopiesMatchingBytesWithTransferredMetadata(t *testing.T) {
	root := t.TempDir()
	contents := []byte("already local")
	if err := os.WriteFile(filepath.Join(root, "old"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := metadata.Manifest{Mode: 0o640, Mtime: time.Unix(100, 200), Xattrs: map[string][]byte{"user.test": []byte("reused")}}
	if err := Reuse(root, "new", "old", hashBytes(contents), manifest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, contents) {
		t.Fatalf("reused bytes = %q, want %q", got, contents)
	}
	if err := metadata.Verify(filepath.Join(root, "new"), manifest); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryMetadataAppliedAfterChildrenAndDeletesUseTrash(t *testing.T) {
	root := t.TempDir()
	dataHome := filepath.Join(root, "data")
	if err := os.MkdirAll(dataHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", dataHome)
	childManifest := metadata.Manifest{Mode: 0o750, Mtime: time.Unix(100, 20)}
	parentManifest := metadata.Manifest{Mode: 0o710, Mtime: time.Unix(90, 10)}
	if err := ApplyDirectory(root, "tree/child", childManifest); err != nil {
		t.Fatal(err)
	}
	if err := ApplyDirectory(root, "tree", parentManifest); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Verify(filepath.Join(root, "tree", "child"), childManifest); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Verify(filepath.Join(root, "tree"), parentManifest); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDirectory(root, "tree/child"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDirectory(root, "tree"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "tree")); !os.IsNotExist(err) {
		t.Fatalf("old directory stat = %v, want absent after trash move", err)
	}
	trashed, err := filepath.Glob(filepath.Join(dataHome, "Trash", "files", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(trashed) != 2 {
		t.Fatalf("trash entries = %v, want child and tree", trashed)
	}
}

func TestDeleteDirectoryRetainsOutOfSetChildren(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "folder")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ignored.swp"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DeleteDirectory(root, "folder"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "ignored.swp")); err != nil {
		t.Fatalf("out-of-set child was removed: %v", err)
	}
}

func TestDirectoryCapabilityFailureLeavesTargetUnchanged(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "folder")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := metadata.Manifest{Mode: 0o755, Mtime: time.Unix(10, 0), ACLDefault: []byte{1}}
	if err := ApplyDirectory(root, "folder", manifest); err == nil {
		t.Fatal("ApplyDirectory error = nil for unsupported ACL declaration")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %#o, want unchanged 0700", info.Mode().Perm())
	}
}

func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:])
}

func testACL(uid uint32) []byte {
	const (
		aclVersion  = 2
		undefinedID = ^uint32(0)
	)
	type entry struct {
		tag  uint16
		perm uint16
		id   uint32
	}
	entries := []entry{{1, 7, undefinedID}, {2, 4, uid}, {4, 5, undefinedID}, {16, 5, undefinedID}, {32, 0, undefinedID}}
	value := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(value, aclVersion)
	for index, item := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(value[offset:], item.tag)
		binary.LittleEndian.PutUint16(value[offset+2:], item.perm)
		binary.LittleEndian.PutUint32(value[offset+4:], item.id)
	}
	return value
}

func TestPreserveConflictKeepsExtension(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.md")
	if err := os.WriteFile(path, []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreserveConflict(root, "note.md", "phone"); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(root, "note.l2sync-conflict-*-phone.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("conflict files = %v", matches)
	}
	if strings.HasSuffix(matches[0], ".txt") {
		t.Fatal("conflict extension changed")
	}
}

func TestWriteHashMismatchLeavesNoPartialDestination(t *testing.T) {
	root := t.TempDir()
	err := Write(root, "nested/file.txt", bytes.NewBufferString("wrong"), strings.Repeat("0", 64))
	if err == nil {
		t.Fatal("Write() error = nil for hash mismatch")
	}
	if _, statErr := os.Stat(filepath.Join(root, "nested", "file.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("destination stat error = %v, want not exists", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(root, "nested", ".l2sync-apply-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestMutationsRejectSymlinkAncestors(t *testing.T) {
	manifest := metadata.Manifest{Mode: 0o700, Mtime: time.Unix(10, 0)}
	operations := map[string]func(string) error{
		"write": func(root string) error {
			return Write(root, "escape/new", bytes.NewBufferString("new"), "")
		},
		"apply directory": func(root string) error {
			return ApplyDirectory(root, "escape/new", manifest)
		},
		"delete": func(root string) error {
			return Delete(root, "escape/file")
		},
		"delete directory": func(root string) error {
			return DeleteDirectory(root, "escape/empty")
		},
		"preserve conflict": func(root string) error {
			return PreserveConflict(root, "escape/file", "phone")
		},
		"reuse": func(root string) error {
			return Reuse(root, "new", "escape/file", hashBytes([]byte("outside")), metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0)})
		},
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "share")
			outside := filepath.Join(base, "outside")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(outside, "empty"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
				t.Fatal(err)
			}
			if err := operation(root); err == nil {
				t.Fatal("mutation through symlink ancestor succeeded")
			}
			contents, err := os.ReadFile(filepath.Join(outside, "file"))
			if err != nil || string(contents) != "outside" {
				t.Fatalf("outside file changed: contents=%q error=%v", contents, err)
			}
			if _, err := os.Stat(filepath.Join(outside, "new")); !os.IsNotExist(err) {
				t.Fatalf("outside target stat = %v, want absent", err)
			}
		})
	}
}

func TestReuseCopiesOneAnchoredSourceDescriptorAcrossPathSubstitution(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		name := "leaf"
		if ancestor {
			name = "ancestor"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "dir")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(directory, "source")
			inside := []byte("inside")
			if err := os.WriteFile(source, inside, 0o600); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			outsideFile := filepath.Join(outside, "source")
			if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			original := afterReuseOpen
			afterReuseOpen = func() {
				if ancestor {
					if err := os.Rename(directory, filepath.Join(root, "held")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, directory); err != nil {
						t.Fatal(err)
					}
					return
				}
				if err := os.Rename(source, filepath.Join(directory, "held")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outsideFile, source); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { afterReuseOpen = original })
			manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0)}
			if err := Reuse(root, "new", "dir/source", hashBytes(inside), manifest); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(filepath.Join(root, "new"))
			if err != nil || !bytes.Equal(contents, inside) {
				t.Fatalf("reused contents = %q, %v", contents, err)
			}
			outsideContents, err := os.ReadFile(outsideFile)
			if err != nil || string(outsideContents) != "outside" {
				t.Fatalf("outside contents = %q, %v", outsideContents, err)
			}
		})
	}
}

func TestPostWriteVerificationRejectsSymlinkSubstitution(t *testing.T) {
	for _, ancestor := range []bool{false, true} {
		name := "leaf"
		if ancestor {
			name = "ancestor"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "file"), []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			original := beforeInstalledVerify
			beforeInstalledVerify = func() {
				directory := filepath.Join(root, "dir")
				if ancestor {
					if err := os.Rename(directory, filepath.Join(root, "held")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, directory); err != nil {
						t.Fatal(err)
					}
					return
				}
				destination := filepath.Join(directory, "file")
				if err := os.Rename(destination, filepath.Join(directory, "held")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "file"), destination); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { beforeInstalledVerify = original })
			contents := []byte("installed")
			manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0)}
			if err := WriteWithMetadata(root, "dir/file", bytes.NewReader(contents), hashBytes(contents), manifest); err == nil {
				t.Fatal("write accepted a symlink substitution before verification")
			}
			outsideContents, err := os.ReadFile(filepath.Join(outside, "file"))
			if err != nil || string(outsideContents) != "outside" {
				t.Fatalf("outside contents = %q, %v", outsideContents, err)
			}
		})
	}
}

func TestConflictPeerMustBeSafeFilenameSegment(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note"), []byte("local"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []string{"../outside", "folder/peer", "peer.name", "peer name"} {
		if err := PreserveConflict(root, "note", peer); err == nil {
			t.Fatalf("PreserveConflict peer %q succeeded", peer)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "note")); err != nil {
		t.Fatalf("canonical file changed after rejected peer: %v", err)
	}
}

func TestConflictSuffixConvergesWinnerAndLoserOnBothReplicas(t *testing.T) {
	leftRoot := t.TempDir()
	rightRoot := t.TempDir()
	loser := []byte("losing bytes")
	winner := []byte("winning bytes")
	for _, root := range []string{leftRoot, rightRoot} {
		if err := os.WriteFile(filepath.Join(root, "note.txt"), loser, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rightRoot, "note.txt"), winner, 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := "20260823-163045-abcdef123456"
	manifest := metadata.Manifest{Mode: 0o600, Mtime: time.Unix(100, 0)}
	winnerHash := fmt.Sprintf("%x", sha256.Sum256(winner))
	loserHash := fmt.Sprintf("%x", sha256.Sum256(loser))
	if err := WriteConflictWinnerWithSuffix(leftRoot, "note.txt", suffix, bytes.NewReader(winner), winnerHash, manifest); err != nil {
		t.Fatal(err)
	}
	if err := WriteConflictCopyWithSuffix(rightRoot, "note.txt", suffix, bytes.NewReader(loser), loserHash, manifest); err != nil {
		t.Fatal(err)
	}
	artifact := "note.l2sync-conflict-" + suffix + ".txt"
	for _, root := range []string{leftRoot, rightRoot} {
		canonical, err := os.ReadFile(filepath.Join(root, "note.txt"))
		if err != nil || !bytes.Equal(canonical, winner) {
			t.Fatalf("canonical in %s = %q, %v", root, canonical, err)
		}
		preserved, err := os.ReadFile(filepath.Join(root, artifact))
		if err != nil || !bytes.Equal(preserved, loser) {
			t.Fatalf("artifact in %s = %q, %v", root, preserved, err)
		}
	}
}

func TestExactConflictCollisionFailsWithoutChoosingReplicaLocalSuffix(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("canonical"), 0o600); err != nil {
		t.Fatal(err)
	}
	suffix := "20260823-120000-aaaaaaaaaaaa"
	artifact := filepath.Join(root, "note.l2sync-conflict-"+suffix+".txt")
	if err := os.WriteFile(artifact, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreserveConflictWithSuffix(root, "note.txt", suffix); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("PreserveConflictWithSuffix error = %v", err)
	}
	if err := WriteConflictCopyWithSuffix(root, "note.txt", suffix, strings.NewReader("loser"), "", metadata.Manifest{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("WriteConflictCopyWithSuffix error = %v", err)
	}
	canonical, err := os.ReadFile(filepath.Join(root, "note.txt"))
	if err != nil || string(canonical) != "canonical" {
		t.Fatalf("canonical = %q, %v", canonical, err)
	}
	unrelated, err := os.ReadFile(artifact)
	if err != nil || string(unrelated) != "unrelated" {
		t.Fatalf("pre-existing artifact = %q, %v", unrelated, err)
	}
	if matches, _ := filepath.Glob(artifact + ".*"); len(matches) != 0 {
		t.Fatalf("replica-local collision suffixes created: %v", matches)
	}
}

func TestConflictFinalCommitCannotReplaceRacingArtifact(t *testing.T) {
	for _, operation := range []string{"preserve", "copy"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("canonical"), 0o600); err != nil {
				t.Fatal(err)
			}
			suffix := "20260823-120000-aaaaaaaaaaaa"
			artifact := filepath.Join(root, "note.l2sync-conflict-"+suffix+".txt")
			originalHook := beforeConflictCommit
			beforeConflictCommit = func() {
				if err := os.WriteFile(artifact, []byte("racing artifact"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { beforeConflictCommit = originalHook })
			var err error
			if operation == "preserve" {
				err = PreserveConflictWithSuffix(root, "note.txt", suffix)
			} else {
				contents := []byte("loser")
				hash := fmt.Sprintf("%x", sha256.Sum256(contents))
				err = WriteConflictCopyWithSuffix(root, "note.txt", suffix, bytes.NewReader(contents), hash, metadata.Manifest{Mode: 0o600, Mtime: time.Unix(10, 0)})
			}
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("operation error = %v", err)
			}
			got, readErr := os.ReadFile(artifact)
			if readErr != nil || string(got) != "racing artifact" {
				t.Fatalf("artifact = %q, %v", got, readErr)
			}
			canonical, readErr := os.ReadFile(filepath.Join(root, "note.txt"))
			if readErr != nil || string(canonical) != "canonical" {
				t.Fatalf("canonical = %q, %v", canonical, readErr)
			}
		})
	}
}
