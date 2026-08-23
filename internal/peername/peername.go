// Package peername validates peer identifiers used in generated filenames.
package peername

import (
	"errors"
	"fmt"
	"unicode"
)

// Validate requires one ASCII filename segment from the same conservative
// alphabet used by registered share names.
func Validate(peer string) error {
	if peer == "" || peer == "." || peer == ".." {
		return errors.New("peer name must be one safe filename segment")
	}
	for _, character := range peer {
		if character > unicode.MaxASCII || !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_') {
			return fmt.Errorf("invalid peer name %q", peer)
		}
	}
	return nil
}
