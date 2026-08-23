package sharename

import (
	"errors"
)

// Validate enforces the canonical lowercase ASCII folder label used by config,
// protocol requests, markers, and CLI commands.
func Validate(name string) error {
	if name == "" {
		return errors.New("folder name must not be empty")
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return errors.New("folder name must contain only lowercase ASCII letters, numbers, hyphens, or underscores")
	}
	return nil
}
