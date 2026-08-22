package config

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const commitOne = "a3a3dda3bacf61e8a39258a0ed9c924eeca8e293"
const commitTwo = "b3a3dda3bacf61e8a39258a0ed9c924eeca8e293"

func TestGlobalPathFollowsXDGAndLoadIsReadOnly(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	filename, err := GlobalPath()
	if err != nil {
		t.Fatal(err)
	}
	if filename != filepath.Join(xdg, "sphinx", "config.yaml") {
		t.Fatalf("GlobalPath = %q", filename)
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	data := "version: 1\ntombs:\n  company:\n    reference: github:acme/secrets.git?ref=main\n"
	if err := os.WriteFile(filename, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	global, err := LoadGlobal(context.Background(), filename, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := global.Tombs["company"].Reference; got != "github:acme/secrets?ref=main" {
		t.Fatalf("canonical global reference = %q", got)
	}
	before, _ := os.ReadFile(filename)
	if _, _, err := ResolveEnrollment(context.Background(), "company", "", global, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filename)
	if string(before) != string(after) {
		t.Fatal("global alias discovery modified its file")
	}
}

func TestProjectStrictRoundTripSelectionAndDefaultBehavior(t *testing.T) {
	project := Project{Version: 1, Tombs: map[string]ProjectTomb{
		"default": {Reference: "github:acme/default?ref=main", Lock: validLock(commitOne)},
		"release": {Reference: "github:acme/release?rev=" + commitTwo, Lock: validLock(commitTwo), Guardians: []GuardianSelection{{Name: "personal", Provider: "apple-icloud-keychain"}}},
	}}
	data, err := EncodeProject(project)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProject(context.Background(), data, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := decoded.Select(context.Background(), "", t.TempDir())
	if err != nil || name != "default" {
		t.Fatalf("default selection = %q, %v", name, err)
	}
	name, _, err = decoded.Select(context.Background(), "github:acme/release?rev="+commitTwo, t.TempDir())
	if err != nil || name != "release" {
		t.Fatalf("canonical selection = %q, %v", name, err)
	}
	delete(decoded.Tombs, "default")
	if _, _, err := decoded.Select(context.Background(), "", t.TempDir()); err == nil {
		t.Fatal("omitted selection unexpectedly fell back to the only tomb")
	}
}

func TestDecodeRejectsAmbiguityAndUnsafeConfiguration(t *testing.T) {
	fingerprint := fingerprint()
	tests := map[string]string{
		"unknown field":                  "version: 1\ntombs: {}\nunknown: true\n",
		"duplicate reference":            "version: 1\ntombs:\n  one:\n    reference: github:acme/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", decree_generation: 1, locked_at: 2026-01-01T00:00:00Z}\n  two:\n    reference: github:acme/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", decree_generation: 1, locked_at: 2026-01-01T00:00:00Z}\n",
		"legacy default":                 "version: 1\ndefault_tomb: one\ntombs: {}\n",
		"legacy locator":                 "version: 1\ntombs:\n  one:\n    locator: github:acme/tomb\n",
		"missing generation":             "version: 1\ntombs:\n  one:\n    reference: github:acme/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", locked_at: 2026-01-01T00:00:00Z}\n",
		"embedded credential":            "version: 1\ntombs:\n  one:\n    reference: git+https://user:secret@example.com/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", decree_generation: 1, locked_at: 2026-01-01T00:00:00Z}\n",
		"duplicate guardian":             "version: 1\ntombs:\n  one:\n    reference: github:acme/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", decree_generation: 1, locked_at: 2026-01-01T00:00:00Z}\n    guardians:\n      - {name: same}\n      - {name: same, provider: apple-login-keychain}\n",
		"multiple environment guardians": "version: 1\ntombs:\n  one:\n    reference: github:acme/tomb\n    lock: {commit: " + commitOne + ", proclamation_fingerprint: " + fingerprint + ", decree_generation: 1, locked_at: 2026-01-01T00:00:00Z}\n    guardians:\n      - {name: first, provider: environment}\n      - {name: second, provider: environment}\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProject(context.Background(), []byte(input), t.TempDir()); err == nil {
				t.Fatal("DecodeProject unexpectedly succeeded")
			}
		})
	}
}

func TestDiscoverUsesNearestWorktreeAndRejectsSymlinkedSphinx(t *testing.T) {
	root := projectRepository(t)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Discover(context.Background(), nested)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(root)
	if store.Root != resolved {
		t.Fatalf("project root = %q, want %q", store.Root, resolved)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, ".sphinx")); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), root); err == nil {
		t.Fatal("Discover unexpectedly accepted symlinked .sphinx")
	}
}

func TestDiscoverSelectsNestedLinkedWorktreeRoot(t *testing.T) {
	root := projectRepository(t)
	command := exec.Command("git", "-C", root, "commit", "--allow-empty", "-m", "initial")
	command.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Sphinx", "GIT_AUTHOR_EMAIL=sphinx@example.invalid", "GIT_COMMITTER_NAME=Sphinx", "GIT_COMMITTER_EMAIL=sphinx@example.invalid")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	command = exec.Command("git", "-C", root, "branch", "nested")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git branch: %v: %s", err, output)
	}
	nested := filepath.Join(t.TempDir(), "nested")
	command = exec.Command("git", "-C", root, "worktree", "add", "--quiet", nested, "nested")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git worktree: %v: %s", err, output)
	}
	store, err := Discover(context.Background(), nested)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(nested)
	if store.Root != resolved {
		t.Fatalf("nested project root = %q, want %q", store.Root, resolved)
	}
}

func TestStoreSerializesConcurrentUpdates(t *testing.T) {
	root := projectRepository(t)
	store, err := Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errors := make(chan error, 8)
	for index := range 8 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			name := string(rune('a' + index))
			errors <- store.Add(context.Background(), name, ProjectTomb{Reference: "github:acme/tomb-" + name, Lock: validLock(commitOne)})
		}(index)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	project, err := store.Load(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(project.Tombs) != 8 {
		t.Fatalf("project has %d tombs", len(project.Tombs))
	}
}

func TestStoreRejectsSymlinkedInterprocessLock(t *testing.T) {
	root := projectRepository(t)
	store, err := Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(store.GitDir, "sphinx-project-config.lock")
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), lockPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(context.Background(), "one", ProjectTomb{Reference: "github:acme/one", Lock: validLock(commitOne)}); err == nil {
		t.Fatal("Store unexpectedly followed a symlinked interprocess lock")
	}
}

func TestUpdateLocksIsAllOrNothing(t *testing.T) {
	root := projectRepository(t)
	store, _ := Discover(context.Background(), root)
	for _, name := range []string{"one", "two"} {
		if err := store.Add(context.Background(), name, ProjectTomb{Reference: "github:acme/" + name, Lock: validLock(commitOne)}); err != nil {
			t.Fatal(err)
		}
	}
	proposals := []LockProposal{
		{Name: "one", ExpectedCommit: commitOne, Lock: validLock(commitTwo)},
		{Name: "two", ExpectedCommit: commitOne, Lock: validLock(commitTwo), Validate: func(context.Context) error { return os.ErrInvalid }},
	}
	if err := store.UpdateLocks(context.Background(), proposals); err == nil {
		t.Fatal("UpdateLocks unexpectedly succeeded")
	}
	project, err := store.Load(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for name, tomb := range project.Tombs {
		if tomb.Lock.Commit != commitOne {
			t.Fatalf("tomb %q was partially updated", name)
		}
	}
}

func TestResolveEnrollmentUsesAliasOrRepositoryBasename(t *testing.T) {
	global := &Global{Version: 1, Tombs: map[string]GlobalTomb{"company": {Reference: "github:acme/secrets?ref=main"}}}
	name, _, err := ResolveEnrollment(context.Background(), "company", "", global, t.TempDir())
	if err != nil || name != "company" {
		t.Fatalf("alias enrollment = %q, %v", name, err)
	}
	name, _, err = ResolveEnrollment(context.Background(), "git+https://git.example.com/acme/release.git?ref=main", "", global, t.TempDir())
	if err != nil || name != "release" {
		t.Fatalf("direct enrollment = %q, %v", name, err)
	}
}

func validLock(commit string) Lock {
	return Lock{Commit: commit, ProclamationFingerprint: fingerprint(), DecreeGeneration: 1, LockedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func fingerprint() string {
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
}

func projectRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return root
}
