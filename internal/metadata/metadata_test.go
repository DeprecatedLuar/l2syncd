//go:build linux

package metadata

import (
	"strings"
	"syscall"
	"testing"
)

func TestValidateRegularRejectsUnreproducibleProperties(t *testing.T) {
	tests := []struct {
		name string
		stat syscall.Stat_t
		want string
	}{
		{"foreign uid", syscall.Stat_t{Uid: 2, Gid: 1, Nlink: 1}, "owner"},
		{"foreign gid", syscall.Stat_t{Uid: 1, Gid: 2, Nlink: 1}, "group"},
		{"hard link", syscall.Stat_t{Uid: 1, Gid: 1, Nlink: 2}, "hard link"},
		{"setuid", syscall.Stat_t{Uid: 1, Gid: 1, Nlink: 1, Mode: syscall.S_ISUID}, "special permission"},
		{"setgid", syscall.Stat_t{Uid: 1, Gid: 1, Nlink: 1, Mode: syscall.S_ISGID}, "special permission"},
		{"sticky", syscall.Stat_t{Uid: 1, Gid: 1, Nlink: 1, Mode: syscall.S_ISVTX}, "special permission"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRegular("fixture", &test.stat, 1, 1)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateRegular error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSupportedXattrClassification(t *testing.T) {
	tests := map[string]bool{
		"user.comment":             true,
		"system.posix_acl_access":  true,
		"system.posix_acl_default": true,
		"security.selinux":         false,
		"security.capability":      false,
		"trusted.overlay.origin":   false,
		"system.other":             false,
	}
	for name, want := range tests {
		if got := supportedXattr(name); got != want {
			t.Errorf("supportedXattr(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestEqualDistinguishesEmptyXattrNames(t *testing.T) {
	left := Manifest{Xattrs: map[string][]byte{"user.left": nil}}
	right := Manifest{Xattrs: map[string][]byte{"user.right": nil}}
	if Equal(left, right) {
		t.Fatal("manifests with different empty xattrs compare equal")
	}
}
