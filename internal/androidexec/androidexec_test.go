//go:build linux

package androidexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandContextPassesThroughWithoutLinker(t *testing.T) {
	if systemLinker() != "" {
		t.Skip("host provides an Android linker; passthrough is not exercised here")
	}
	command, err := CommandContext(context.Background(), "sh", "-c", "true")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(command.Path) != "sh" {
		t.Fatalf("command.Path = %q, want an sh path", command.Path)
	}
	if got := command.Args[1:]; len(got) != 2 || got[0] != "-c" || got[1] != "true" {
		t.Fatalf("command.Args = %q, want the caller's arguments unchanged", command.Args)
	}
}

func TestCommandContextReportsMissingExecutable(t *testing.T) {
	if systemLinker() == "" {
		t.Skip("lookup happens lazily in exec.CommandContext without a linker")
	}
	if _, err := CommandContext(context.Background(), "l2sync-absent-binary", "-x"); err == nil {
		t.Fatal("CommandContext accepted a missing executable")
	}
}

func TestDirectExecAllowed(t *testing.T) {
	for _, test := range []struct {
		path string
		want bool
	}{
		{"/system/bin/ssh", true},
		{"/apex/com.android.runtime/bin/linker64", true},
		{"/vendor/bin/tool", true},
		{"/data/data/com.termux/files/usr/bin/ssh", false},
		{"/usr/bin/ssh", false},
	} {
		if got := directExecAllowed(test.path); got != test.want {
			t.Errorf("directExecAllowed(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

// TestCommandContextRoutesThroughLinker verifies the rewrite's argument
// shape without needing an Android host: the linker consumes argv[0] and
// loads argv[1], so the resolved executable must lead the argument list and
// the caller's arguments must follow it untouched.
func TestCommandContextRoutesThroughLinker(t *testing.T) {
	linker := systemLinker()
	if linker == "" {
		t.Skip("no Android linker on this host")
	}
	resolved, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if directExecAllowed(resolved) {
		t.Skip("test binary lives on a directly executable partition")
	}
	command, err := CommandContext(context.Background(), resolved, "-x")
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != linker {
		t.Fatalf("command.Path = %q, want the linker %q", command.Path, linker)
	}
	if len(command.Args) != 3 || !strings.HasSuffix(command.Args[1], filepath.Base(resolved)) || command.Args[2] != "-x" {
		t.Fatalf("command.Args = %q, want [linker, resolved, -x]", command.Args)
	}
}
