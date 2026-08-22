package lock

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/config"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/locator"
)

func TestResolveDeterministicallyUsesApprovedCommitAndFixedArtifactPath(t *testing.T) {
	root, commit := tombRepository(t)
	canonical, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	project := config.Project{Version: 1, Tombs: map[string]config.ProjectTomb{
		"default": {Reference: canonical.String(), Lock: lock(commit)},
	}}
	resolver := Resolver{Materializer: gitresource.Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}}
	resolved, err := resolver.Resolve(context.Background(), project, "", root, "Production/API")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Commit != commit || resolved.Blob.Path != "Production/API/artifact.yaml" || string(resolved.Blob.Data) != "approved ciphertext\n" {
		t.Fatalf("resolved artifact = %#v", resolved)
	}
	if schema, err := resolved.ReadSchema("api-key/v1"); err != nil || !strings.Contains(string(schema.Data), "name: api-key") {
		t.Fatalf("ReadSchema = %q, %v", schema.Data, err)
	}

	// A later worktree change cannot alter the already approved object blob.
	write(t, root, "Production/API/artifact.yaml", "unapproved bytes\n")
	again, err := resolver.Resolve(context.Background(), project, "path:"+root, root, "Production/API")
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Blob.Data) != "approved ciphertext\n" {
		t.Fatalf("resolved mutable worktree bytes %q", again.Blob.Data)
	}
}

func TestResolvePreservesCaseAndRequiresProjectApproval(t *testing.T) {
	root, commit := tombRepository(t)
	canonical, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	project := config.Project{Version: 1, Tombs: map[string]config.ProjectTomb{
		"only": {Reference: canonical.String(), Lock: lock(commit)},
	}}
	resolver := Resolver{Materializer: gitresource.Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}}
	if _, err := resolver.Resolve(context.Background(), project, "", root, "Production/API"); err == nil {
		t.Fatal("Resolve unexpectedly used the sole tomb as an implicit default")
	}
	if _, err := resolver.Resolve(context.Background(), project, "only", root, "production/api"); err == nil {
		t.Fatal("Resolve unexpectedly case-folded the chamber")
	}
	if _, err := resolver.Resolve(context.Background(), project, "github:other/tomb", root, "Production/API"); err == nil {
		t.Fatal("Resolve unexpectedly accepted an unlocked reference")
	}
}

func tombRepository(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	run(t, root, "init", "--quiet", "--initial-branch=main")
	run(t, root, "config", "user.name", "Sphinx Test")
	run(t, root, "config", "user.email", "sphinx@example.invalid")
	write(t, root, ".tomb/tomb.yaml", "version: 1\n")
	write(t, root, ".tomb/decree.yaml", "version: 1\n")
	write(t, root, ".tomb/decree.yaml.sig", "version: 1\n")
	write(t, root, ".tomb/rotations/.keep", "")
	write(t, root, ".tomb/schemas/api-key/v1.yaml", "version: 1\nname: api-key\nsecrets:\n  - name: value\n    type: string\n    required: true\n    prompt: Value\n")
	write(t, root, "Production/API/artifact.yaml", "approved ciphertext\n")
	run(t, root, "add", ".")
	run(t, root, "commit", "--quiet", "-m", "approved")
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved, strings.TrimSpace(string(output))
}

func lock(commit string) config.Lock {
	return config.Lock{Commit: commit, ProclamationFingerprint: "SHA256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), DecreeGeneration: 1, LockedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func write(t *testing.T, root, name, value string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
