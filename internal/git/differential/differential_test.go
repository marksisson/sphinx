package differential

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	gitruntime "github.com/marksisson/sphinx/internal/git/runtime"
)

func TestMain(m *testing.M) {
	if err := gitruntime.Initialize(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func TestFoundationalLocalOperationsMatchNativeGit(t *testing.T) {
	for _, objectFormat := range []string{"sha1", "sha256"} {
		t.Run(objectFormat, func(t *testing.T) {
			fixture := createRepository(t, objectFormat)
			before := snapshotAdministrativeFiles(t, fixture.root)
			ctx := context.Background()
			native, candidate := nativeAdapter{}, goGitAdapter{}

			for _, start := range []string{fixture.root, filepath.Join(fixture.root, "nested", "deeper")} {
				want, err := native.Discover(ctx, start)
				if err != nil {
					t.Fatalf("%s discover: %v", native.Name(), err)
				}
				got, err := candidate.Discover(ctx, start)
				if err != nil {
					t.Fatalf("%s discover: %v", candidate.Name(), err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("discover(%q) disagreement\n%s: %+v\n%s: %+v", start, native.Name(), want, candidate.Name(), got)
				}
			}

			wantHead, err := native.Head(ctx, fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			gotHead, err := candidate.Head(ctx, fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			if gotHead != wantHead || gotHead != fixture.secondCommit {
				t.Fatalf("HEAD disagreement: native=%s go-git=%s fixture=%s", wantHead, gotHead, fixture.secondCommit)
			}

			for _, commit := range []string{fixture.firstCommit, fixture.secondCommit} {
				if err := native.CommitExists(ctx, fixture.root, commit); err != nil {
					t.Fatalf("native commit %s: %v", commit, err)
				}
				if err := candidate.CommitExists(ctx, fixture.root, commit); err != nil {
					t.Fatalf("go-git commit %s: %v", commit, err)
				}
				assertTreesEqual(t, ctx, native, candidate, fixture.root, commit)
			}

			for _, path := range []string{"artifact.yaml", "nested/deeper/value.txt", "literal/[abc]*?.txt", "executable.sh", "symbolic-link"} {
				want, err := native.ReadBlob(ctx, fixture.root, fixture.secondCommit, path)
				if err != nil {
					t.Fatalf("native blob %q: %v", path, err)
				}
				got, err := candidate.ReadBlob(ctx, fixture.root, fixture.secondCommit, path)
				if err != nil {
					t.Fatalf("go-git blob %q: %v", path, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("blob %q disagreement\nnative: %+v\ngo-git: %+v", path, want, got)
				}
			}

			for _, data := range [][]byte{nil, []byte("plain bytes\n"), []byte("binary\x00bytes\xff")} {
				want, err := native.HashBlob(ctx, fixture.root, data)
				if err != nil {
					t.Fatal(err)
				}
				got, err := candidate.HashBlob(ctx, fixture.root, data)
				if err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("blob object ID disagreement for %d bytes: native=%s go-git=%s", len(data), want, got)
				}
			}

			for _, check := range []struct {
				ancestor   string
				descendant string
				want       bool
			}{
				{fixture.firstCommit, fixture.secondCommit, true},
				{fixture.secondCommit, fixture.firstCommit, false},
				{fixture.secondCommit, fixture.secondCommit, true},
			} {
				nativeResult, err := native.IsAncestor(ctx, fixture.root, check.ancestor, check.descendant)
				if err != nil {
					t.Fatal(err)
				}
				candidateResult, err := candidate.IsAncestor(ctx, fixture.root, check.ancestor, check.descendant)
				if err != nil {
					t.Fatal(err)
				}
				if nativeResult != check.want || candidateResult != nativeResult {
					t.Fatalf("ancestry disagreement: native=%v go-git=%v want=%v", nativeResult, candidateResult, check.want)
				}
			}

			missing := strings.Repeat("0", len(fixture.secondCommit))
			if err := native.CommitExists(ctx, fixture.root, missing); err == nil {
				t.Fatal("native Git accepted missing commit")
			}
			if err := candidate.CommitExists(ctx, fixture.root, missing); err == nil {
				t.Fatal("go-git accepted missing commit")
			}
			if _, err := native.ReadBlob(ctx, fixture.root, fixture.secondCommit, "missing"); err == nil {
				t.Fatal("native Git accepted missing blob path")
			}
			if _, err := candidate.ReadBlob(ctx, fixture.root, fixture.secondCommit, "missing"); err == nil {
				t.Fatal("go-git accepted missing blob path")
			}

			after := snapshotAdministrativeFiles(t, fixture.root)
			if !reflect.DeepEqual(after, before) {
				t.Fatal("read-only differential operations changed Git administrative bytes")
			}
		})
	}
}

func TestDiscoveryMatchesForNativeLinkedDetachedAndBareWorktrees(t *testing.T) {
	fixture := createRepository(t, "sha1")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, fixture.root, "worktree", "add", "-q", "-b", "linked-test", linked, fixture.secondCommit)
	bare := filepath.Join(t.TempDir(), "bare.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, bare)
	runGit(t, fixture.root, "checkout", "-q", "--detach", fixture.firstCommit)

	ctx := context.Background()
	for _, start := range []string{
		filepath.Join(fixture.root, "nested"),
		filepath.Join(linked, "nested"),
		bare,
	} {
		want, err := (nativeAdapter{}).Discover(ctx, start)
		if err != nil {
			t.Fatalf("native discover %q: %v", start, err)
		}
		got, err := (goGitAdapter{}).Discover(ctx, start)
		if err != nil {
			t.Fatalf("go-git discover %q: %v", start, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("discover %q disagreement: native=%+v go-git=%+v", start, want, got)
		}
	}
}

func assertTreesEqual(t *testing.T, ctx context.Context, native, candidate adapter, repository, commit string) {
	t.Helper()
	want, err := native.ListTree(ctx, repository, commit)
	if err != nil {
		t.Fatalf("%s tree: %v", native.Name(), err)
	}
	got, err := candidate.ListTree(ctx, repository, commit)
	if err != nil {
		t.Fatalf("%s tree: %v", candidate.Name(), err)
	}
	sortTree(want)
	sortTree(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree disagreement\n%s: %#v\n%s: %#v", native.Name(), want, candidate.Name(), got)
	}
}

type repositoryFixture struct {
	root         string
	firstCommit  string
	secondCommit string
}

func createRepository(t *testing.T, objectFormat string) repositoryFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repository")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "-q", "--object-format="+objectFormat)
	runGit(t, root, "config", "user.name", "Differential Test")
	runGit(t, root, "config", "user.email", "differential@example.invalid")
	writeFixture(t, root, "artifact.yaml", "first\n", 0o600)
	writeFixture(t, root, "nested/deeper/value.txt", "nested\x00bytes\n", 0o600)
	writeFixture(t, root, "literal/[abc]*?.txt", "literal pathspec bytes\n", 0o600)
	writeFixture(t, root, "executable.sh", "#!/bin/sh\nexit 0\n", 0o700)
	if err := os.Symlink("artifact.yaml", filepath.Join(root, "symbolic-link")); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "--all")
	runGit(t, root, "commit", "-q", "-m", "first")
	first := gitText(t, root, "rev-parse", "HEAD")

	writeFixture(t, root, "artifact.yaml", "second\n", 0o600)
	writeFixture(t, root, "new.txt", "new\n", 0o600)
	runGit(t, root, "add", "--all")
	runGit(t, root, "commit", "-q", "-m", "second")
	second := gitText(t, root, "rev-parse", "HEAD")
	runGit(t, root, "tag", "lightweight", first)
	runGit(t, root, "tag", "-a", "-m", "annotated", "annotated", second)
	runGit(t, root, "gc", "--prune=now")

	return repositoryFixture{root: root, firstCommit: first, secondCommit: second}
}

func writeFixture(t *testing.T, root, name, value string, mode os.FileMode) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	if output, err := nativeGit(context.Background(), root, arguments...); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func gitText(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	output, err := nativeGit(context.Background(), root, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func snapshotAdministrativeFiles(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	gitDirectory := gitText(t, root, "rev-parse", "--absolute-git-dir")
	commonDirectory := gitText(t, root, "rev-parse", "--git-common-dir")
	if !filepath.IsAbs(commonDirectory) {
		commonDirectory = filepath.Join(root, commonDirectory)
	}
	roots := []string{filepath.Clean(gitDirectory)}
	if filepath.Clean(commonDirectory) != filepath.Clean(gitDirectory) {
		roots = append(roots, filepath.Clean(commonDirectory))
	}
	sort.Strings(roots)
	result := make(map[string][32]byte)
	for _, administrativeRoot := range roots {
		err := filepath.WalkDir(administrativeRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(administrativeRoot, path)
			if err != nil {
				return err
			}
			key := fmt.Sprintf("%s:%s", administrativeRoot, filepath.ToSlash(relative))
			result[key] = sha256.Sum256(data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}
