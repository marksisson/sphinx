//go:build darwin

// Package hardening establishes process controls required before Sphinx loads
// private identities or decrypted plaintext.
package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// DisableCoreDumps irreversibly sets both the soft and hard core-file size
// limits to zero for this process and its children. A failure must abort the
// command before sensitive material is loaded.
func DisableCoreDumps() error {
	limit := unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		return fmt.Errorf("set macOS core-size limit to zero: %w", err)
	}
	var established unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &established); err != nil {
		return fmt.Errorf("verify macOS core-size limit: %w", err)
	}
	if established.Cur != 0 || established.Max != 0 {
		return fmt.Errorf("verify macOS core-size limit: expected soft and hard limits of zero")
	}
	return nil
}
