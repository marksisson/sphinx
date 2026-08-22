package phase8

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestSecurityAndOperationalPublicationsExist(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		"docs/security/THREAT_MODEL_REVIEW.md",
		"docs/release/SUPPORT_MATRIX.md",
		"docs/release/RELEASE.md",
		"docs/operations/RECOVERY.md",
		"docs/operations/GUARDIAN_COMPROMISE.md",
		"docs/operations/PROCLAMATION_ROTATION.md",
		"docs/operations/ROLLBACK.md",
		"scripts/build-release-macos.sh",
		"scripts/verify-release-candidate.sh",
	} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

func TestReleaseProcedureRequiresSigningNotarizationAndPublishedEvidence(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts/build-release-macos.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"SPHINX_CODESIGN_IDENTITY", "--options runtime", "--timestamp", "notarytool submit", "status: Accepted", "stapler staple", "stapler validate", "darwin-arm64.dmg", "context:primary-signature", "spctl --assess", "sbom.cdx.json", "SHA256SUMS", "GOARCH=arm64", "CGO_ENABLED=1", "-buildmode=pie", "-trimpath", "source_commit"} {
		if !strings.Contains(text, required) {
			t.Fatalf("release procedure lacks %q", required)
		}
	}
}

func TestNoPlaintextTemporaryOrLoggingBoundaryInSensitivePackages(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"cmd/sphinx", "internal/artifact", "internal/proclamation", "internal/reveal"} {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, forbidden := range []string{"os.CreateTemp", "os.WriteFile", "log.Print", "slog.", "exec.Command"} {
				if strings.Contains(text, forbidden) {
					t.Fatalf("%s/%s contains forbidden sensitive boundary %q", directory, entry.Name(), forbidden)
				}
			}
		}
	}
}
