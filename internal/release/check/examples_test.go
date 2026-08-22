package check

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/decree"
	"github.com/marksisson/sphinx/internal/schema"
)

func root(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate release-check test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root(t), name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReleaseExamplesDecode(t *testing.T) {
	if _, err := schema.Decode(read(t, "docs/examples/schema.yaml")); err != nil {
		t.Fatalf("schema example: %v", err)
	}
	if _, err := decree.Decode(read(t, "docs/examples/decree.yaml")); err != nil {
		t.Fatalf("decree example: %v", err)
	}
	if _, err := config.DecodeProject(context.Background(), read(t, "docs/examples/project-config.yaml"), root(t)); err != nil {
		t.Fatalf("project example: %v", err)
	}
	filename := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(filename, read(t, "docs/examples/global-config.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadGlobal(context.Background(), filename, root(t)); err != nil {
		t.Fatalf("global example: %v", err)
	}
}

func TestUnsupportedServiceAndAuditTreesAreAbsent(t *testing.T) {
	for _, name := range []string{"internal/audit", "internal/identity", "internal/policy", "internal/relic", "internal/secret", "internal/server", "internal/tombref", "launchd", "artifacts/sphinx-vs-setec.html"} {
		if _, err := os.Lstat(filepath.Join(root(t), name)); !os.IsNotExist(err) {
			t.Errorf("unsupported path exists: %s", name)
		}
	}
}

func TestReleaseMatrixIsAppleSiliconOnly(t *testing.T) {
	flake := string(read(t, "flake.nix"))
	if strings.Count(flake, "aarch64-darwin") != 2 {
		t.Fatalf("unexpected aarch64-darwin declarations")
	}
	for _, unsupported := range []string{"aarch64-linux", "x86_64-linux", "x86_64-darwin"} {
		if strings.Contains(flake, unsupported) {
			t.Fatalf("unsupported release target remains: %s", unsupported)
		}
	}
}

func TestDocumentationNamesFinalCommandGroups(t *testing.T) {
	readme := string(read(t, "README.md"))
	for _, group := range []string{"sphinx tomb", "sphinx artifact", "sphinx guardian", "sphinx decree", "sphinx proclamation"} {
		if !strings.Contains(readme, group) {
			t.Errorf("README does not document %s", group)
		}
	}
}
