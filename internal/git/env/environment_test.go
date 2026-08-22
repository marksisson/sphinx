package env

import (
	"strings"
	"testing"
)

func TestEnvironmentRemovesGitRedirection(t *testing.T) {
	t.Setenv("GIT_DIR", "/attacker")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/attacker")
	for _, entry := range Environment() {
		if strings.HasPrefix(entry, "GIT_DIR=") || strings.HasPrefix(entry, "GIT_CONFIG_COUNT=") || strings.HasPrefix(entry, "GIT_CONFIG_KEY_") || strings.HasPrefix(entry, "GIT_CONFIG_VALUE_") {
			t.Fatalf("unsafe environment entry survived: %q", entry)
		}
	}
}
