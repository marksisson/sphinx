package worktree

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

func TestGuardRejectsSymlinkedIndex(t *testing.T) {
	root := repository(t)
	index := filepath.Join(root, ".git", "index")
	actual := filepath.Join(root, ".git", "index.actual")
	if err := os.Rename(index, actual); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, index); err != nil {
		t.Fatal(err)
	}
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("symlinked Git index was accepted")
	}
}

func TestGuardRejectsRawConflictStagesWithoutOperationMarker(t *testing.T) {
	root := repository(t)
	runGit(t, root, "checkout", "-q", "-b", "other")
	writeFile(t, root, "service/artifact.yaml", "other\n")
	runGit(t, root, "add", "service/artifact.yaml")
	runGit(t, root, "commit", "-q", "-m", "other")
	other := gitText(t, root, "rev-parse", "HEAD")
	runGit(t, root, "checkout", "-q", "main")
	writeFile(t, root, "service/artifact.yaml", "main\n")
	runGit(t, root, "add", "service/artifact.yaml")
	runGit(t, root, "commit", "-q", "-m", "main")
	if output, err := gitCommand(root, "merge", "--no-commit", "--no-ff", other).CombinedOutput(); err == nil {
		t.Fatalf("merge unexpectedly succeeded: %s", output)
	}
	if err := os.Remove(filepath.Join(root, ".git", "MERGE_HEAD")); err != nil {
		t.Fatal(err)
	}
	worktree, err := Open(context.Background(), "path:"+root, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
		t.Fatal("raw conflict stages were accepted without an operation marker")
	}
}

func TestGuardConservativelyRejectsIndexFlagsThatHideWorktreeChanges(t *testing.T) {
	for _, flag := range []string{"--skip-worktree", "--assume-unchanged"} {
		t.Run(flag, func(t *testing.T) {
			root := repository(t)
			runGit(t, root, "update-index", flag, "service/artifact.yaml")
			writeFile(t, root, "service/artifact.yaml", "hidden by index flag\n")
			if output := nativeStatus(t, root, "service/artifact.yaml"); len(output) != 0 {
				t.Fatalf("native status unexpectedly reported %q", output)
			}
			worktree, _ := Open(context.Background(), "path:"+root, root, "")
			if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
				t.Fatal("index flag hid a mutation target change")
			}
		})
	}
}

func TestIntentToAddIsConservativelyRejectedWithExtendedIndex(t *testing.T) {
	root := repository(t)
	writeFile(t, root, "intent.yaml", "intent\n")
	runGit(t, root, "add", "-N", "intent.yaml")
	status := nativeStatus(t, root, "intent.yaml")
	if len(status) < 2 || status[0] != ' ' {
		t.Fatalf("native intent-to-add status = %q", status)
	}
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	if _, err := worktree.GuardMutationInputs(context.Background(), []string{"intent.yaml"}, []string{"intent.yaml"}); err == nil {
		t.Fatal("extended intent-to-add index was accepted")
	}
}

func TestGuardRejectsUnsupportedIndexVersions(t *testing.T) {
	for _, version := range []string{"3", "4"} {
		t.Run("v"+version, func(t *testing.T) {
			root := repository(t)
			if version == "3" {
				runGit(t, root, "update-index", "--skip-worktree", "service/artifact.yaml")
			}
			runGit(t, root, "update-index", "--index-version="+version)
			worktree, _ := Open(context.Background(), "path:"+root, root, "")
			if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
				t.Fatalf("index v%s was accepted", version)
			}
		})
	}
}

func TestGuardEvaluatesCommittedNestedAndInformationAttributes(t *testing.T) {
	for name, install := range map[string]func(*testing.T, string){
		"committed": func(t *testing.T, root string) {
			writeFile(t, root, ".gitattributes", "service/artifact.yaml filter=lfs\n")
			runGit(t, root, "add", ".gitattributes")
			runGit(t, root, "commit", "-q", "-m", "unsafe committed attributes")
			if err := os.Remove(filepath.Join(root, ".gitattributes")); err != nil {
				t.Fatal(err)
			}
		},
		"nested macro": func(t *testing.T, root string) {
			writeFile(t, root, "service/.gitattributes", "[attr]nested -text\n")
		},
		"information": func(t *testing.T, root string) {
			writeFile(t, root, ".git/info/attributes", "service/artifact.yaml working-tree-encoding=UTF-16\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := repository(t)
			install(t, root)
			worktree, _ := Open(context.Background(), "path:"+root, root, "")
			if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err == nil {
				t.Fatal("unsafe attributes were accepted")
			}
		})
	}
}

func TestMutationInspectionDoesNotModifyAdministrativeBytes(t *testing.T) {
	root := repository(t)
	worktree, _ := Open(context.Background(), "path:"+root, root, "")
	before := snapshotGitDirectory(t, filepath.Join(root, ".git"))
	if _, err := worktree.GuardMutation(context.Background(), []string{"service/artifact.yaml"}); err != nil {
		t.Fatal(err)
	}
	after := snapshotGitDirectory(t, filepath.Join(root, ".git"))
	if !reflect.DeepEqual(after, before) {
		t.Fatal("mutation inspection changed Git administrative bytes")
	}
}

func TestProspectiveBlobUsesRepositoryObjectFormat(t *testing.T) {
	for _, objectFormat := range []string{"sha1", "sha256"} {
		t.Run(objectFormat, func(t *testing.T) {
			root := repositoryWithFormat(t, objectFormat)
			worktree, _ := Open(context.Background(), "path:"+root, root, "")
			data := []byte("prospective bytes\n")
			got, err := worktree.hashBlob(context.Background(), data)
			if err != nil {
				t.Fatal(err)
			}
			command := gitCommand(root, "hash-object", "--no-filters", "--stdin")
			command.Stdin = bytes.NewReader(data)
			want, err := command.Output()
			if err != nil {
				t.Fatal(err)
			}
			if got != string(bytes.TrimSpace(want)) {
				t.Fatalf("object ID = %q, want %q", got, want)
			}
		})
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
	return repositoryWithFormat(t, "sha1")
}

func repositoryWithFormat(t *testing.T, objectFormat string) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet", "--initial-branch=main", "--object-format="+objectFormat)
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

func snapshotGitDirectory(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		result[relative] = string(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func nativeStatus(t *testing.T, root, target string) []byte {
	t.Helper()
	output, err := gitCommand(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ":(literal)"+target).Output()
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func gitText(t *testing.T, root string, args ...string) string {
	t.Helper()
	output, err := gitCommand(root, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(output))
}

func gitCommand(root string, args ...string) *exec.Cmd {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	return command
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := gitCommand(root, args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
