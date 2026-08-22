package check

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
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func TestSecurityAndOperationalPublicationsExist(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		"docs/security/THREAT_MODEL.md",
		"docs/release/SUPPORT_MATRIX.md",
		"docs/release/PROCESS.md",
		"docs/operations/RECOVERY.md",
		"docs/operations/GUARDIAN_COMPROMISE.md",
		"docs/operations/PROCLAMATION_ROTATION.md",
		"docs/operations/ROLLBACK.md",
		"scripts/build-release-macos.sh",
		"scripts/verify.sh",
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

func TestRuntimePackagingAndProductionCodeRequireNoGitExecutable(t *testing.T) {
	root := repositoryRoot(t)
	flake, err := os.ReadFile(filepath.Join(root, "flake.nix"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pkgs.makeWrapper", "wrapProgram", "makeBinPath [ pkgs.git ]"} {
		if strings.Contains(string(flake), forbidden) {
			t.Fatalf("runtime package still contains %q", forbidden)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "git", "env")); !os.IsNotExist(err) {
		t.Fatal("transitional internal/git/env package remains")
	}
	for _, script := range []string{"scripts/verify-release-candidate.sh", "scripts/build-release-macos.sh"} {
		data, err := os.ReadFile(filepath.Join(root, script))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "PATH=") {
			t.Fatalf("%s lacks empty-PATH candidate execution", script)
		}
	}
}

func TestGitTransportPolicyRemainsVerifiedAndNoninteractive(t *testing.T) {
	filename := filepath.Join(repositoryRoot(t), "internal", "git", "transport", "transport.go")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"FollowInitialRedirects", "MinVersion: tls.VersionTLS12", "Proxy:", "standardKnownHostsFiles", "SSH_AUTH_SOCK", "secureRedirect", "SafeError"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Git transport policy lacks %q", required)
		}
	}
	for _, forbidden := range []string{"WithInsecureSkipTLS", "WithProxyEnvironment", "WithHTTPAuth", "InsecureIgnoreHostKey", "DefaultUserSettings", "NewSSHAgentAuth("} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Git transport policy contains forbidden behavior %q", forbidden)
		}
	}
}

func TestWorktreeDiscoveryAndMutationSafetyDoNotInvokeNativeGit(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"internal/config", "internal/locator", "internal/git/repository", "internal/git/worktree"} {
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
			for _, forbidden := range []string{"os/exec", "internal/git/env", "exec.Command"} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("%s/%s contains native Git boundary %q", directory, entry.Name(), forbidden)
				}
			}
		}
	}
}

func TestImmutableGitResourcesDoNotInvokeNativeGit(t *testing.T) {
	directory := filepath.Join(repositoryRoot(t), "internal", "git", "resource")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"os/exec", "internal/git/env", "exec.Command"} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("internal/git/resource/%s contains native Git boundary %q", entry.Name(), forbidden)
			}
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
