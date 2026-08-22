package worktree

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOpenRequiresExplicitRootPathAndRejectsCache(t *testing.T) {
	root := repository(t)
	if _, err := Open(context.Background(), "github:example/tomb", root, ""); err == nil {
		t.Fatal("Open unexpectedly accepted a remote reference")
	}
	if _, err := Open(context.Background(), "path:.", filepath.Join(root, "nested"), ""); err == nil {
		t.Fatal("Open unexpectedly accepted a worktree subdirectory")
	}
	if _, err := Open(context.Background(), "path:"+root, root, filepath.Dir(root)); err == nil {
		t.Fatal("Open unexpectedly accepted a cache-contained worktree")
	}
	opened, err := Open(context.Background(), "path:"+root, root, "")
	if err != nil || opened.Root == "" || opened.GitDir == "" {
		t.Fatalf("Open = %#v, %v", opened, err)
	}
}

func TestGuardMutationAllowsUnrelatedDirtButRejectsTargetDirt(t *testing.T) {
	root := repository(t)
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	writeFile(t, root, "README.md", "unrelated dirty\n")
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err != nil {
		t.Fatalf("unrelated dirt was rejected: %v", err)
	}
	writeFile(t, root, "service/artifact.yaml", "changed\n")
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("unstaged target dirt was accepted")
	}
	runGit(t, root, "add", "service/artifact.yaml")
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("staged target dirt was accepted")
	}
}

func TestGuardMutationInputsAllowsUnstagedButRejectsStagedInput(t *testing.T) {
	root := repository(t)
	tree, err := Open(context.Background(), "path:"+root, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.GuardMutationInputs(context.Background(), []string{"target.txt"}, []string{"target.txt"}); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "target.txt")
	if _, err := tree.GuardMutationInputs(context.Background(), []string{"target.txt"}, []string{"target.txt"}); err == nil {
		t.Fatal("staged editable input accepted")
	}
}

func TestGuardRejectsSymlinksAttributesAndInProgressOperations(t *testing.T) {
	root := repository(t)
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.GuardMutation(context.Background(), []string{"linked/artifact.yaml"}); err == nil {
		t.Fatal("symlink target was accepted")
	}
	if err := os.Remove(filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, ".gitattributes", "service/artifact.yaml filter=lfs\n")
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("filtered target was accepted")
	}
	if err := os.Remove(filepath.Join(root, ".gitattributes")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree.GitDir, "MERGE_HEAD"), []byte("test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("in-progress Git operation was accepted")
	}
}

func TestGuardDetectsTOCTOUAndProspectiveBlobHashesExactBytes(t *testing.T) {
	root := repository(t)
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	guard, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "service/artifact.yaml", "third party\r\nbytes\n")
	if err := guard.Revalidate(context.Background()); err == nil {
		t.Fatal("Revalidate missed a target change")
	}
	data, digest, err := worktree.ProspectiveBlob(context.Background(), "service/artifact.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("third party\r\nbytes\n")) || digest == [32]byte{} {
		t.Fatalf("ProspectiveBlob = %q, %x", data, digest)
	}
}

func TestNestedWorktreeDiscoveryUsesNestedRoot(t *testing.T) {
	root := repository(t)
	branch := "nested-worktree"
	runGit(t, root, "branch", branch)
	nested := filepath.Join(t.TempDir(), "nested")
	runGit(t, root, "worktree", "add", "--quiet", nested, branch)
	resolved, err := filepath.EvalSymlinks(nested)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(context.Background(), "path:"+resolved, resolved, "")
	if err != nil {
		t.Fatal(err)
	}
	if opened.Root != resolved || opened.GitDir == filepath.Join(root, ".git") {
		t.Fatalf("nested worktree = %#v", opened)
	}
}

func repository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet", "--initial-branch=main")
	runGit(t, root, "config", "user.name", "Sphinx Test")
	runGit(t, root, "config", "user.email", "sphinx@example.invalid")
	writeFile(t, root, "service/artifact.yaml", "original\n")
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "--quiet", "-m", "initial")
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func writeFile(t *testing.T, root, name, value string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
