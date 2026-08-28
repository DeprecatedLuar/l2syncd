//go:build linux

// Package androidexec builds subprocess commands that remain executable
// under Android's W^X restriction.
//
// Android 10+ refuses to exec ELF files stored in an app's private data
// directory, which is where all of Termux lives. Termux normally hides this
// with termux-exec, an LD_PRELOAD shim that rewrites libc's execve() into
// "run the system linker, and hand it the real binary". That interception
// only covers callers that go through libc.
//
// Go never does. syscall.forkAndExecInChild issues RawSyscall(SYS_EXECVE)
// directly on every Linux build, cgo or not, because the child of a fork
// must not take locks or allocate. So l2sync's subprocesses bypass the shim
// and Android denies them, reported as "fork/exec ...: permission denied".
// Building with CGO_ENABLED=1 does not change this.
//
// This package therefore performs the same rewrite termux-exec would have,
// explicitly. On any host without the Android linker it is a passthrough.
package androidexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LinkerNames are the Android dynamic linker binaries, 64-bit first. Android
// runs an ELF handed to the linker as an argument even when execing that ELF
// directly is refused, because the kernel only ever sees the linker (which
// lives on a partition permitted to exec) being started.
var LinkerNames = []string{"linker64", "linker"}

// linkerDir holds the Android dynamic linker. Its absence is what identifies
// a non-Android host, so no separate platform probe is needed.
const linkerDir = "/system/bin"

// execAllowedPrefixes are the read-only Android partitions whose binaries the
// kernel will exec directly. Routing those through the linker is unnecessary,
// so they are left alone.
var execAllowedPrefixes = []string{"/system/", "/apex/", "/vendor/"}

// CommandContext returns a command that runs name with args, rewritten to
// start through the Android dynamic linker when that is required for the
// exec to be permitted. Off Android it is equivalent to
// exec.CommandContext. Unlike exec.CommandContext it reports lookup failure
// immediately rather than deferring it to Run, because the rewrite has to
// resolve the executable's real path up front.
func CommandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	linker := systemLinker()
	if linker == "" {
		return exec.CommandContext(ctx, name, args...), nil
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("locate %s: %w", name, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	if directExecAllowed(resolved) {
		return exec.CommandContext(ctx, resolved, args...), nil
	}
	// The linker consumes argv[0] (itself) and treats argv[1] as the program
	// to load, handing that program argv[1:]. Passing resolved as the first
	// argument therefore leaves args in place and makes resolved the
	// program's own argv[0], matching a direct exec.
	return exec.CommandContext(ctx, linker, append([]string{resolved}, args...)...), nil
}

// systemLinker returns the Android dynamic linker, or "" when this host has
// none and direct exec is unrestricted.
func systemLinker() string {
	for _, name := range LinkerNames {
		path := filepath.Join(linkerDir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// directExecAllowed reports whether Android will exec path without help.
func directExecAllowed(path string) bool {
	for _, prefix := range execAllowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
