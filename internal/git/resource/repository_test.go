package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/marksisson/sphinx/internal/locator"
)

func TestMaterializeAndValidateExactObjectDatabaseContent(t *testing.T) {
	root, commit := createTomb(t)
	reference, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "cache")
	repository, err := (Materializer{CacheRoot: cache}).Materialize(context.Background(), reference, commit)
	if err != nil {
		t.Fatal(err)
	}
	content, err := repository.ValidateContent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	artifact := content.Artifacts["Production/API"]
	if !bytes.Equal(artifact.Data, []byte("format: 1\npayload: ciphertext\n")) {
		t.Fatalf("artifact blob bytes = %q", artifact.Data)
	}
	if artifact.SHA256() != sha256.Sum256([]byte("format: 1\npayload: ciphertext\n")) || len(artifact.SHA256Hex()) != 64 {
		t.Fatalf("artifact SHA-256 = %s", artifact.SHA256Hex())
	}
	if _, err := os.Stat(filepath.Join(repository.gitDirectory, "Production", "API", "artifact.yaml")); !os.IsNotExist(err) {
		t.Fatal("immutable object cache unexpectedly contains a worktree checkout")
	}
	if mode := mustStat(t, cache).Mode().Perm(); mode != 0o700 {
		t.Fatalf("cache mode = %#o", mode)
	}
}

func TestMaterializeIsRaceSafeAndRepairsCorruption(t *testing.T) {
	root, commit := createTomb(t)
	reference, _ := locator.ParseAt(context.Background(), "path:"+root, root)
	materializer := Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}
	var wait sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := materializer.Materialize(context.Background(), reference, commit)
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	repository, err := materializer.Materialize(context.Background(), reference, commit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(repository.gitDirectory, "objects")); err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Materialize(context.Background(), reference, commit); err != nil {
		t.Fatalf("corrupt cache was not repaired: %v", err)
	}
}

func TestMaterializeRejectsSymlinkedCacheLock(t *testing.T) {
	root, commit := createTomb(t)
	reference, _ := locator.ParseAt(context.Background(), "path:"+root, root)
	materializer := Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}
	if _, err := materializer.Materialize(context.Background(), reference, commit); err != nil {
		t.Fatal(err)
	}
	locks, err := filepath.Glob(filepath.Join(materializer.CacheRoot, "locks", "*.lock"))
	if err != nil || len(locks) != 1 {
		t.Fatalf("cache locks = %v, %v", locks, err)
	}
	if err := os.Remove(locks[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), locks[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := materializer.Materialize(context.Background(), reference, commit); err == nil {
		t.Fatal("Materialize unexpectedly followed a symlinked cache lock")
	}
}

func TestValidateContentRejectsUnsafeManagedEntries(t *testing.T) {
	tests := map[string]func(string){
		"LFS pointer": func(root string) {
			write(t, root, "Production/API/artifact.yaml", "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n")
		},
		"invalid YAML framing": func(root string) {
			write(t, root, "Production/API/artifact.yaml", "format: 1\r\n")
		},
		"filter": func(root string) {
			write(t, root, ".gitattributes", "Production/API/artifact.yaml filter=unsafe\n")
		},
		"encoding": func(root string) {
			write(t, root, ".gitattributes", "Production/API/artifact.yaml working-tree-encoding=UTF-16\n")
		},
		"line endings": func(root string) {
			write(t, root, ".gitattributes", "Production/API/artifact.yaml text eol=lf\n")
		},
		"alternate metadata": func(root string) {
			write(t, root, ".sphinx/tomb.yaml", "alternate\n")
		},
		"non-sequence rotation": func(root string) {
			write(t, root, ".tomb/rotations/latest.yaml", "version: 1\n")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root, _ := createTomb(t)
			mutate(root)
			switch name {
			case "filter", "encoding", "line endings":
				runGit(t, root, "add", ".gitattributes")
			case "LFS pointer", "invalid YAML framing":
				runGit(t, root, "add", "Production/API/artifact.yaml")
			case "alternate metadata":
				runGit(t, root, "add", ".sphinx/tomb.yaml")
			default:
				runGit(t, root, "add", ".tomb/rotations/latest.yaml")
			}
			runGit(t, root, "commit", "--quiet", "-m", name)
			commit := gitText(t, root, "rev-parse", "HEAD")
			reference, _ := locator.ParseAt(context.Background(), "path:"+root, root)
			repository, err := (Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, commit)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repository.ValidateContent(context.Background()); err == nil {
				t.Fatal("ValidateContent unexpectedly succeeded")
			}
		})
	}
}

func TestValidateContentPreservesExactCaseAndCaseCollisions(t *testing.T) {
	root, _ := createTomb(t)
	blobOID := gitInput(t, root, []byte("other\n"), "hash-object", "-w", "--stdin")
	runGit(t, root, "update-index", "--add", "--cacheinfo", "100644,"+blobOID+",production/api/artifact.yaml")
	runGit(t, root, "commit", "--quiet", "-m", "case collision")
	commit := gitText(t, root, "rev-parse", "HEAD")
	reference, _ := locator.ParseAt(context.Background(), "path:"+root, root)
	repository, err := (Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, commit)
	if err != nil {
		t.Fatal(err)
	}
	content, err := repository.ValidateContent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, upper := content.Artifacts["Production/API"]; !upper {
		t.Fatal("upper-case chamber missing")
	}
	if _, lower := content.Artifacts["production/api"]; !lower {
		t.Fatal("lower-case chamber missing")
	}
}

func TestResolveCommitReadsExplicitPathWorktreeHEAD(t *testing.T) {
	root, commit := createTomb(t)
	reference, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveCommit(context.Background(), reference)
	if err != nil || resolved != commit {
		t.Fatalf("resolved=%q want=%q err=%v", resolved, commit, err)
	}
}

func TestResolveCommitRejectsAmbiguousBranchAndTag(t *testing.T) {
	root, _ := createTomb(t)
	runGit(t, root, "branch", "collision")
	runGit(t, root, "tag", "collision")
	_, err := locator.ParseAt(context.Background(), "path:"+root+"?ref=collision", root)
	if err == nil {
		t.Fatal("path reference unexpectedly accepted a selector")
	}
	base, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	base.Ref = "collision"
	if _, err := ResolveCommit(context.Background(), base); err == nil {
		t.Fatal("ResolveCommit unexpectedly accepted an ambiguous branch/tag")
	}
}

func TestDescendantCheck(t *testing.T) {
	root, first := createTomb(t)
	write(t, root, "README.md", "next\n")
	runGit(t, root, "add", "README.md")
	runGit(t, root, "commit", "--quiet", "-m", "next")
	second := gitText(t, root, "rev-parse", "HEAD")
	reference, _ := locator.ParseAt(context.Background(), "path:"+root, root)
	repository, err := (Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, second)
	if err != nil {
		t.Fatal(err)
	}
	if descendant, err := repository.IsDescendant(context.Background(), first, second); err != nil || !descendant {
		t.Fatalf("descendant = %v, %v", descendant, err)
	}
	if descendant, err := repository.IsDescendant(context.Background(), second, first); err != nil || descendant {
		t.Fatalf("reverse descendant = %v, %v", descendant, err)
	}
}

func createTomb(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet", "--initial-branch=main")
	runGit(t, root, "config", "user.name", "Sphinx Test")
	runGit(t, root, "config", "user.email", "sphinx@example.invalid")
	write(t, root, ".tomb/tomb.yaml", "version: 1\n")
	write(t, root, ".tomb/decree.yaml", "version: 1\n")
	write(t, root, ".tomb/decree.yaml.sig", "version: 1\n")
	write(t, root, ".tomb/rotations/.keep", "")
	write(t, root, ".tomb/schemas/api-key/v1.yaml", "version: 1\nname: api-key\nsecrets:\n  - name: value\n    type: string\n    required: true\n    prompt: Value\n")
	write(t, root, "Production/API/artifact.yaml", "format: 1\npayload: ciphertext\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "--quiet", "-m", "initial tomb")
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved, gitText(t, root, "rev-parse", "HEAD")
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

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func gitText(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(output))
}

func gitInput(t *testing.T, root string, input []byte, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(output))
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
