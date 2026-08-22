package repository

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDiscoverWorktreeMatchesNativeMainDetachedAndLinkedWorktrees(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "tracked"), "tracked\n")
	runGit(t, root, "add", "tracked")
	runGit(t, root, "commit", "-q", "-m", "initial")

	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, root, "worktree", "add", "-q", "-b", "linked-test", linked)
	runGit(t, root, "checkout", "-q", "--detach")

	for name, worktree := range map[string]string{"detached-main": root, "linked": linked} {
		t.Run(name, func(t *testing.T) {
			nested := filepath.Join(worktree, "a", "b")
			if err := os.MkdirAll(nested, 0o700); err != nil {
				t.Fatal(err)
			}
			got, err := DiscoverWorktree(context.Background(), nested)
			if err != nil {
				t.Fatal(err)
			}
			wantRoot := nativePath(t, worktree, "rev-parse", "--show-toplevel")
			wantGit := nativePath(t, worktree, "rev-parse", "--absolute-git-dir")
			wantCommon := nativeText(t, worktree, "rev-parse", "--git-common-dir")
			if !filepath.IsAbs(wantCommon) {
				wantCommon = filepath.Join(worktree, wantCommon)
			}
			wantCommon, _ = filepath.EvalSymlinks(wantCommon)
			if got.Root != wantRoot || got.GitDir != wantGit || got.CommonDir != wantCommon {
				t.Fatalf("discovery = %#v, want root=%q git=%q common=%q", got, wantRoot, wantGit, wantCommon)
			}
		})
	}
}

func TestDiscoveryDoesNotModifyAdministrativeBytes(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "tracked"), "tracked\n")
	runGit(t, root, "add", "tracked")
	runGit(t, root, "commit", "-q", "-m", "initial")
	before := snapshotTree(t, filepath.Join(root, ".git"))
	if _, err := DiscoverWorktree(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	after := snapshotTree(t, filepath.Join(root, ".git"))
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("worktree discovery modified Git administrative bytes")
	}
}

func TestDiscoverWorktreeSupportsUnbornHEAD(t *testing.T) {
	root := initializeRepository(t)
	got, err := DiscoverWorktree(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != root || got.GitDir != filepath.Join(root, ".git") || got.CommonDir != got.GitDir {
		t.Fatalf("unborn discovery = %#v", got)
	}
}

func TestOpenWorktreeRequiresExactRootAndRejectsBareRepository(t *testing.T) {
	root := initializeRepository(t)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWorktree(context.Background(), nested); err == nil {
		t.Fatal("OpenWorktree accepted a nested path")
	}
	bare := filepath.Join(root, "nested-bare.git")
	runGit(t, t.TempDir(), "init", "-q", "--bare", bare)
	if _, err := DiscoverWorktree(context.Background(), bare); err == nil {
		t.Fatal("DiscoverWorktree accepted a nested bare repository or selected its outer worktree")
	}
}

func TestMalformedInnerDotGitFailsClosedInsteadOfSelectingOuterRepository(t *testing.T) {
	outer := initializeRepository(t)
	inner := filepath.Join(outer, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, ".git"), []byte("gitdir: missing\nsecond line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverWorktree(context.Background(), inner); err == nil {
		t.Fatal("malformed inner .git metadata was skipped")
	}
}

func TestDiscoveryRejectsOversizedOrSymlinkedAdministrativeMetadata(t *testing.T) {
	for name, install := range map[string]func(*testing.T, string){
		"oversized": func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".git"), bytes.Repeat([]byte{'x'}, administrativeFileLimit+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, root string) {
			actual := filepath.Join(root, "actual.git")
			if err := os.Rename(filepath.Join(root, ".git"), actual); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(actual, filepath.Join(root, ".git")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := initializeRepository(t)
			install(t, root)
			if _, err := DiscoverWorktree(context.Background(), root); err == nil {
				t.Fatal("unsafe administrative metadata was accepted")
			}
		})
	}
}

func TestDiscoveryRejectsMalformedLinkedWorktreeCommonMetadata(t *testing.T) {
	root := initializeRepository(t)
	writeFile(t, filepath.Join(root, "tracked"), "tracked\n")
	runGit(t, root, "add", "tracked")
	runGit(t, root, "commit", "-q", "-m", "initial")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, root, "worktree", "add", "-q", "-b", "linked-malformed", linked)
	gitDirectory := nativePath(t, linked, "rev-parse", "--absolute-git-dir")
	commonPath := filepath.Join(gitDirectory, "commondir")
	if err := os.Remove(commonPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".git"), commonPath); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverWorktree(context.Background(), linked); err == nil {
		t.Fatal("symlinked linked-worktree common metadata was accepted")
	}
}

func TestDiscoveryHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiscoverWorktree(ctx, t.TempDir()); err == nil {
		t.Fatal("cancelled discovery succeeded")
	}
}

func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			result[relative] = "symlink:" + target
			return nil
		}
		if entry.IsDir() {
			result[relative] = "directory"
			return nil
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

func initializeRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q", "--initial-branch=main")
	runGit(t, root, "config", "user.name", "Discovery Test")
	runGit(t, root, "config", "user.email", "discovery@example.invalid")
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func writeFile(t *testing.T, name, value string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func nativePath(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	value := nativeText(t, root, arguments...)
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func nativeText(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(output))
}
