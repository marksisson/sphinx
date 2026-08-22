package lock

import (
	"context"
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

func TestPrepareAndInstallDescendantUpdate(t *testing.T) {
	tombRoot, first := tombRepository(t)
	canonical, _ := locator.ParseAt(context.Background(), "path:"+tombRoot, tombRoot)
	projectRoot := projectGit(t)
	store, _ := config.Discover(context.Background(), projectRoot)
	if err := store.Add(context.Background(), "default", config.ProjectTomb{Reference: canonical.String(), Lock: lock(first)}); err != nil {
		t.Fatal(err)
	}
	write(t, tombRoot, "README.md", "descendant\n")
	run(t, tombRoot, "add", "README.md")
	run(t, tombRoot, "commit", "--quiet", "-m", "descendant")
	second := gitOutput(t, tombRoot, "rev-parse", "HEAD")
	project, _ := store.Load(context.Background(), false)
	resolver := Resolver{Materializer: gitresource.Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}}
	updates, err := resolver.PrepareUpdates(context.Background(), *project, nil, projectRoot,
		func(_ string, commit string, _ *gitresource.Content) (config.Lock, error) {
			next := lock(commit)
			next.DecreeGeneration = 2
			next.LockedAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
			return next, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 || updates[0].NextCommit() != second {
		t.Fatalf("updates = %#v", updates)
	}

	// A mutable ref moving again cannot substitute a different commit after
	// preparation; installation uses the exact prepared candidate.
	write(t, tombRoot, "README.md", "moved again\n")
	run(t, tombRoot, "add", "README.md")
	run(t, tombRoot, "commit", "--quiet", "-m", "moved again")
	if err := InstallUpdates(context.Background(), store, updates); err != nil {
		t.Fatal(err)
	}
	installed, _ := store.Load(context.Background(), false)
	if got := installed.Tombs["default"].Lock.Commit; got != second {
		t.Fatalf("installed commit = %q, want prepared %q", got, second)
	}
}

func TestPrepareRejectsNonDescendantAndChangesNothing(t *testing.T) {
	tombRoot, first := tombRepository(t)
	canonical, _ := locator.ParseAt(context.Background(), "path:"+tombRoot, tombRoot)
	projectRoot := projectGit(t)
	store, _ := config.Discover(context.Background(), projectRoot)
	if err := store.Add(context.Background(), "default", config.ProjectTomb{Reference: canonical.String(), Lock: lock(first)}); err != nil {
		t.Fatal(err)
	}
	run(t, tombRoot, "checkout", "--quiet", "--orphan", "unrelated")
	run(t, tombRoot, "rm", "-rf", "--quiet", ".")
	// Recreate a valid tomb on unrelated history.
	write(t, tombRoot, ".tomb/tomb.yaml", "version: 1\n")
	write(t, tombRoot, ".tomb/decree.yaml", "version: 1\n")
	write(t, tombRoot, ".tomb/decree.yaml.sig", "version: 1\n")
	write(t, tombRoot, ".tomb/rotations/.keep", "")
	write(t, tombRoot, ".tomb/schemas/api-key/v1.yaml", "version: 1\nname: api-key\nsecrets:\n  - name: value\n    type: string\n    required: true\n    prompt: Value\n")
	write(t, tombRoot, "Production/API/artifact.yaml", "unrelated\n")
	run(t, tombRoot, "add", ".")
	run(t, tombRoot, "commit", "--quiet", "-m", "unrelated")
	project, _ := store.Load(context.Background(), false)
	resolver := Resolver{Materializer: gitresource.Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}}
	if _, err := resolver.PrepareUpdates(context.Background(), *project, nil, projectRoot,
		func(_ string, commit string, _ *gitresource.Content) (config.Lock, error) { return lock(commit), nil }); err == nil {
		t.Fatal("PrepareUpdates unexpectedly accepted non-descendant history")
	}
	unchanged, _ := store.Load(context.Background(), false)
	if unchanged.Tombs["default"].Lock.Commit != first {
		t.Fatal("failed preparation changed project config")
	}
}

func projectGit(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return root
}

func gitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}
