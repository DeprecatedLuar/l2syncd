//go:build linux

package main

import (
	"reflect"
	"testing"
)

// The Android system linker layout under test is the one termux-exec's
// modifyExecArgs() produces: [original argv[0], resolved executable path,
// original argv[1:]...].
func TestNormalizeArgs(t *testing.T) {
	const (
		program = "/data/data/com.termux/files/home/bin/l2sync"
		linker  = "/apex/com.android.runtime/bin/linker64"
	)

	cases := []struct {
		name       string
		argv       []string
		executable string
		want       []string
	}{
		{
			name:       "linker launch resolved through PATH",
			argv:       []string{"l2sync", program, "version"},
			executable: linker,
			want:       []string{"l2sync", "version"},
		},
		{
			name:       "linker launch by explicit path",
			argv:       []string{program, program, "status"},
			executable: linker,
			want:       []string{program, "status"},
		},
		{
			name:       "linker launch with no arguments",
			argv:       []string{"l2sync", program},
			executable: linker,
			want:       []string{"l2sync"},
		},
		{
			name:       "linker launch keeps later arguments in order",
			argv:       []string{"l2sync", program, "add", "notes", "--peer", "raspberries"},
			executable: linker,
			want:       []string{"l2sync", "add", "notes", "--peer", "raspberries"},
		},
		{
			name:       "32-bit linker is recognized",
			argv:       []string{"l2sync", program, "version"},
			executable: "/system/bin/linker",
			want:       []string{"l2sync", "version"},
		},
		{
			name:       "direct exec is untouched",
			argv:       []string{"/home/luar/bin/l2sync", "version"},
			executable: "/home/luar/bin/l2sync",
			want:       []string{"/home/luar/bin/l2sync", "version"},
		},
		{
			name:       "direct exec with an absolute path argument is untouched",
			argv:       []string{"l2sync", "/home/luar/Notes", "version"},
			executable: "/home/luar/bin/l2sync",
			want:       []string{"l2sync", "/home/luar/Notes", "version"},
		},
		{
			name:       "linker launch with relative argv[1] is untouched",
			argv:       []string{"l2sync", "version"},
			executable: linker,
			want:       []string{"l2sync", "version"},
		},
		{
			name:       "unresolvable executable is untouched",
			argv:       []string{"l2sync", program, "version"},
			executable: "",
			want:       []string{"l2sync", program, "version"},
		},
		{
			name:       "single element argv is untouched",
			argv:       []string{"l2sync"},
			executable: linker,
			want:       []string{"l2sync"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]string(nil), tc.argv...)
			got := normalizeArgs(tc.argv, tc.executable)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("normalizeArgs(%q, %q) = %q, want %q", original, tc.executable, got, tc.want)
			}
			if !reflect.DeepEqual(tc.argv, original) {
				t.Errorf("normalizeArgs mutated its input: got %q, want %q", tc.argv, original)
			}
		})
	}
}
