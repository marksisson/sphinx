//go:build darwin

package hardening

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestDisableCoreDumpsSetsAndVerifiesBothLimits(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %#v", limit)
	}
	if err := DisableCoreDumps(); err != nil {
		t.Fatalf("idempotent call: %v", err)
	}
}
