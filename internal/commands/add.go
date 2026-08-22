//go:build linux

package commands

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"l2syncd/internal/config"
	"l2syncd/internal/guard"
	"l2syncd/internal/preflight"
)

const (
	shareMarkerDirectory = ".l2sync"
	shareMarkerMode      = 0o700
	addExitOK            = 0
	addExitError         = 1
	addExitInvalid       = 2
)

func add(cfg config.Config, args []string, stderr io.Writer, input io.Reader) int {
	pathArgument, name, nameProvided, ok := parseAddArgs(args, stderr)
	if !ok {
		return addExitError
	}
	path, err := filepath.Abs(pathArgument)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: resolve share path: %v\n", err)
		return addExitError
	}
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: share %q: %v\n", pathArgument, err)
		return addExitError
	}
	if !info.IsDir() {
		fmt.Fprintf(stderr, "l2sync: share %q is not a directory\n", pathArgument)
		return addExitError
	}
	if err := guard.Filesystem(path); err != nil {
		fmt.Fprintf(stderr, "l2sync: share filesystem: %v\n", err)
		return addExitError
	}

	if !nameProvided {
		fmt.Fprint(stderr, "Enter share name: ")
		name, err = readShareName(input)
		if err != nil {
			fmt.Fprintf(stderr, "\nl2sync: read share name: %v\n", err)
			return addExitError
		}
	}
	name = strings.ToLower(name)
	if err := validateShareName(name); err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return addExitError
	}
	if _, exists := cfg.Shares[name]; exists {
		fmt.Fprintf(stderr, "l2sync: share %q already exists\n", name)
		return addExitError
	}
	marker := filepath.Join(path, shareMarkerDirectory)
	if err := os.Mkdir(marker, shareMarkerMode); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(stderr, "l2sync: create share marker: %v\n", err)
		return addExitError
	}
	cfg.Shares[name] = config.Share{Local: path}
	if err := config.Save(cfg); err != nil {
		fmt.Fprintf(stderr, "l2sync: save config: %v\n", err)
		return addExitError
	}
	return addExitOK
}

func parseAddArgs(args []string, stderr io.Writer) (path, name string, nameProvided, ok bool) {
	positionals := make([]string, 0, 2)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--name" || argument == "-n":
			if nameProvided || index+1 >= len(args) || args[index+1] == "" {
				fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
				return "", "", false, false
			}
			name = args[index+1]
			nameProvided = true
			index++
		case strings.HasPrefix(argument, "--name="):
			if nameProvided || strings.TrimPrefix(argument, "--name=") == "" {
				fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
				return "", "", false, false
			}
			name = strings.TrimPrefix(argument, "--name=")
			nameProvided = true
		case argument == "--path" || argument == "-p":
			if path != "" || index+1 >= len(args) || args[index+1] == "" {
				fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
				return "", "", false, false
			}
			path = args[index+1]
			index++
		case strings.HasPrefix(argument, "--path="):
			if path != "" || strings.TrimPrefix(argument, "--path=") == "" {
				fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
				return "", "", false, false
			}
			path = strings.TrimPrefix(argument, "--path=")
		case strings.HasPrefix(argument, "-"):
			fmt.Fprintf(stderr, "l2sync: unknown option %q\n", argument)
			return "", "", false, false
		default:
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) > 2 || (len(positionals) == 2 && (nameProvided || path != "")) {
		fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
		return "", "", false, false
	}
	if len(positionals) == 2 {
		if nameProvided {
			fmt.Fprintln(stderr, "l2sync: share name provided more than once")
			return "", "", false, false
		}
		name = positionals[0]
		nameProvided = true
		if path != "" {
			fmt.Fprintln(stderr, "l2sync: share path provided more than once")
			return "", "", false, false
		}
		path = positionals[1]
	} else if len(positionals) == 1 {
		if path == "" {
			path = positionals[0]
		} else if !nameProvided {
			name = positionals[0]
			nameProvided = true
		} else {
			fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
			return "", "", false, false
		}
	}
	if path == "" {
		fmt.Fprintln(stderr, "usage: l2sync add [name] <path> [--name <name>] [--path <path>]")
		return "", "", false, false
	}
	return path, name, nameProvided, true
}

func readShareName(input io.Reader) (string, error) {
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func validateShareName(name string) error {
	if name == "" {
		return errors.New("share name must not be empty")
	}
	for _, character := range name {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			if character > unicode.MaxASCII {
				return errors.New("share name must contain only ASCII letters, numbers, hyphens, or underscores")
			}
			continue
		}
		if character != '-' && character != '_' {
			return errors.New("share name must contain only ASCII letters, numbers, hyphens, or underscores")
		}
	}
	return nil
}

// Add registers a local directory as a share.
func Add(args []string, stderr io.Writer) int {
	cfg, err := preflight.LoadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "l2sync: %v\n", err)
		return addExitInvalid
	}
	return add(cfg, args, stderr, os.Stdin)
}
