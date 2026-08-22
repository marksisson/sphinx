//go:build !darwin

package hardening

import "fmt"

// DisableCoreDumps is unavailable outside the sole release platform.
func DisableCoreDumps() error {
	return fmt.Errorf("core-dump hardening is supported only on macOS")
}
