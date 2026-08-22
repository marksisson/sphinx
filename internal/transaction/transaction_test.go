package transaction

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marksisson/sphinx/internal/gitenv"
	"github.com/marksisson/sphinx/internal/worktree"
)

func TestExecuteCommitsExactPostImages(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o640}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, err := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	if err != nil {
		t.Fatal(err)
	}
	validator := exactValidator(map[string]string{"one.txt": "new-one\n", "two.txt": "new-two\n"})
	if err := Execute(context.Background(), tree, guard, posts, validator, Options{}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"one.txt": "new-one\n", "two.txt": "new-two\n"} {
		data, _ := os.ReadFile(filepath.Join(tree.Root, path))
		if string(data) != want {
			t.Fatalf("%s = %q", path, data)
		}
	}
	if err := RequireCleanJournal(tree); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteGuardsReadOnlyDependencies(t *testing.T) {
	tree := transactionWorktree(t)
	guard, err := tree.GuardMutation(context.Background(), []string{"one.txt", "unrelated.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.Root, "unrelated.txt"), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	posts := map[string]PostImage{"one.txt": {Data: []byte("new\n"), Mode: 0o600}}
	err = Execute(context.Background(), tree, guard, posts, func(View) error { return nil }, Options{Dependencies: []string{"unrelated.txt"}})
	if err == nil {
		t.Fatal("changed signed dependency accepted")
	}
	if got, _ := os.ReadFile(filepath.Join(tree.Root, "one.txt")); string(got) != "old-one\n" {
		t.Fatalf("target changed to %q", got)
	}
}

func TestOrdinaryFailureRollsBackEveryInstalledPath(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o600}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, _ := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	err := Execute(context.Background(), tree, guard, posts, func(View) error { return nil }, Options{Hook: func(phase string, installed int) error {
		if phase == "installed" && installed == 1 {
			return errors.New("injected")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("injected failure succeeded")
	}
	assertFile(t, tree.Root, "one.txt", "old-one\n")
	assertFile(t, tree.Root, "two.txt", "old-two\n")
	if err := RequireCleanJournal(tree); err != nil {
		t.Fatal(err)
	}
}

func TestCrashLeavesJournalAndRecoveryRestoresOnlyTargets(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o600}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, _ := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected simulated crash")
			}
		}()
		_ = Execute(context.Background(), tree, guard, posts, func(View) error { return nil }, Options{Hook: func(phase string, installed int) error {
			if phase == "installed" && installed == 1 {
				panic("crash")
			}
			return nil
		}})
	}()
	if err := RequireCleanJournal(tree); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("pending journal = %v", err)
	}
	authorized := false
	if err := RecoverRollback(tree, func() error { authorized = true; return nil }, exactValidator(map[string]string{"one.txt": "old-one\n", "two.txt": "old-two\n"})); err != nil {
		t.Fatal(err)
	}
	if !authorized {
		t.Fatal("rollback did not require proclamation authorization")
	}
	assertFile(t, tree.Root, "one.txt", "old-one\n")
	assertFile(t, tree.Root, "two.txt", "old-two\n")
	assertFile(t, tree.Root, "unrelated.txt", "untouched\n")
}

func TestRollbackRefusesUnexpectedThirdPartyEdit(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o600}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, _ := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	err := Execute(context.Background(), tree, guard, posts, func(View) error { return nil }, Options{Hook: func(phase string, installed int) error {
		if phase == "installed" && installed == 1 {
			if err := os.WriteFile(filepath.Join(tree.Root, "one.txt"), []byte("third-party\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return errors.New("stop")
		}
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "third-party") {
		t.Fatalf("third-party rollback = %v", err)
	}
	assertFile(t, tree.Root, "one.txt", "third-party\n")
	if err := RecoverRollback(tree, func() error { return nil }, func(View) error { return nil }); err == nil {
		t.Fatal("recovery overwrote third-party edit")
	}
}

func TestCorruptJournalAndSymlinkedLockFailClosed(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o600}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, _ := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	func() {
		defer func() { _ = recover() }()
		_ = Execute(context.Background(), tree, guard, posts, func(View) error { return nil }, Options{Hook: func(phase string, installed int) error {
			if phase == "prepared" {
				panic("crash")
			}
			return nil
		}})
	}()
	journalPath := filepath.Join(tree.GitDir, "sphinx", "transactions", "current", "journal.json")
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-2], []byte(",\"unknown\":true}\n")...)
	if err := os.WriteFile(journalPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverRollback(tree, func() error { return nil }, func(View) error { return nil }); err == nil {
		t.Fatal("corrupt journal accepted")
	}

	other := transactionWorktree(t)
	lockPath := filepath.Join(other.GitDir, "sphinx-mutation.lock")
	if err := os.Symlink(filepath.Join(other.Root, "unrelated.txt"), lockPath); err != nil {
		t.Fatal(err)
	}
	guard, _ = other.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	if err := Execute(context.Background(), other, guard, posts, func(View) error { return nil }, Options{}); err == nil {
		t.Fatal("symlinked transaction lock accepted")
	}
}

func TestCommittedCrashIsCleanedWithoutRollback(t *testing.T) {
	tree := transactionWorktree(t)
	posts := map[string]PostImage{"one.txt": {Data: []byte("new-one\n"), Mode: 0o600}, "two.txt": {Data: []byte("new-two\n"), Mode: 0o600}}
	guard, _ := tree.GuardMutation(context.Background(), []string{"one.txt", "two.txt"})
	err := Execute(context.Background(), tree, guard, posts, exactValidator(map[string]string{"one.txt": "new-one\n", "two.txt": "new-two\n"}), Options{Hook: func(phase string, _ int) error {
		if phase == "committed" {
			return errors.New("lost response")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("committed hook failure expected")
	}
	called := false
	if err := RecoverRollback(tree, func() error { called = true; return nil }, exactValidator(map[string]string{"one.txt": "new-one\n", "two.txt": "new-two\n"})); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("committed cleanup requested rollback authorization")
	}
	assertFile(t, tree.Root, "one.txt", "new-one\n")
}

func transactionWorktree(t *testing.T) *worktree.Worktree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.invalid")
	runGit(t, root, "config", "user.name", "Test")
	for p, v := range map[string]string{"one.txt": "old-one\n", "two.txt": "old-two\n", "unrelated.txt": "untouched\n"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "initial")
	tree, err := worktree.Open(context.Background(), "path:"+root, root, "")
	if err != nil {
		t.Fatal(err)
	}
	return tree
}
func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = gitenv.Environment()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s", args, out)
	}
}
func assertFile(t *testing.T, root, path, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, path))
	if err != nil || string(data) != want {
		t.Fatalf("%s = %q, %v", path, data, err)
	}
}
func exactValidator(expected map[string]string) Validator {
	return func(view View) error {
		for path, want := range expected {
			data, _, exists, err := view.Read(path)
			if err != nil {
				return err
			}
			if !exists || string(data) != want {
				return errors.New("invalid complete state")
			}
		}
		return nil
	}
}
