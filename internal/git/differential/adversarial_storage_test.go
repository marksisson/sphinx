package differential

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	testgit "github.com/marksisson/sphinx/internal/testgit"
)

func TestRawCaseCollidingAndInvalidUTF8TreeNames(t *testing.T) {
	fixture := createRepository(t, "sha1")
	blobOID := gitInput(t, fixture.root, []byte("raw tree value\n"), "hash-object", "-w", "--stdin")
	// Raw tree entries cannot contain slashes, so construct the case-distinct
	// directories as subtrees and retain invalid UTF-8 at the root.
	caseTree := writeRawTree(t, fixture.root, rawTree(rawTreeEntry{mode: "100644", name: []byte("artifact.yaml"), oid: blobOID}))
	rootTree := writeRawTree(t, fixture.root, rawTree(
		rawTreeEntry{mode: "040000", name: []byte("Case"), oid: caseTree},
		rawTreeEntry{mode: "040000", name: []byte("case"), oid: caseTree},
		rawTreeEntry{mode: "100644", name: []byte{'i', 'n', 'v', 'a', 'l', 'i', 'd', '-', 0xff}, oid: blobOID},
	))
	commit := gitText(t, fixture.root, "commit-tree", "-m", "raw names", rootTree)

	want, err := (nativeAdapter{}).ListTree(context.Background(), fixture.root, commit)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (goGitAdapter{}).ListTree(context.Background(), fixture.root, commit)
	if err != nil {
		t.Fatalf("go-git rejected native-readable exact tree names: %v", err)
	}
	sortTree(want)
	sortTree(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("raw tree disagreement\nnative: %#v\ngo-git: %#v", want, got)
	}
	paths := make(map[string]bool)
	for _, entry := range got {
		paths[entry.Path] = true
	}
	if !paths["Case/artifact.yaml"] || !paths["case/artifact.yaml"] {
		t.Fatal("case-distinct paths were not preserved")
	}
	if !paths[string([]byte{'i', 'n', 'v', 'a', 'l', 'i', 'd', '-', 0xff})] {
		t.Fatal("invalid UTF-8 unrelated path was not preserved as exact bytes")
	}
}

func TestDuplicateRawTreeEntryIsConservativelyRejected(t *testing.T) {
	fixture := createRepository(t, "sha1")
	first := gitInput(t, fixture.root, []byte("first\n"), "hash-object", "-w", "--stdin")
	second := gitInput(t, fixture.root, []byte("second\n"), "hash-object", "-w", "--stdin")
	tree := writeRawTree(t, fixture.root, rawTree(
		rawTreeEntry{mode: "100644", name: []byte("duplicate"), oid: first},
		rawTreeEntry{mode: "100644", name: []byte("duplicate"), oid: second},
	))
	commit := gitText(t, fixture.root, "commit-tree", "-m", "duplicate", tree)
	if _, err := (nativeAdapter{}).ListTree(context.Background(), fixture.root, commit); err != nil {
		t.Fatalf("native Git did not enumerate duplicate raw tree fixture: %v", err)
	}
	if _, err := (goGitAdapter{}).ListTree(context.Background(), fixture.root, commit); err == nil {
		t.Fatal("go-git accepted duplicate raw tree entries")
	}
}

func TestGitlinkModeMatchesNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	tree := writeRawTree(t, fixture.root, rawTree(rawTreeEntry{mode: "160000", name: []byte("submodule"), oid: fixture.firstCommit}))
	commit := gitText(t, fixture.root, "commit-tree", "-m", "gitlink", tree)
	assertTreesEqual(t, context.Background(), nativeAdapter{}, goGitAdapter{}, fixture.root, commit)
}

func TestTruncatedPackFailsClosed(t *testing.T) {
	fixture := createRepository(t, "sha1")
	for _, engine := range []adapter{nativeAdapter{}, goGitAdapter{}} {
		t.Run(engine.Name(), func(t *testing.T) {
			bare := filepath.Join(t.TempDir(), "corrupt.git")
			runGit(t, fixture.root, "clone", "-q", "--bare", "--no-hardlinks", fixture.root, bare)
			runGit(t, bare, "gc", "--prune=now")
			pack := firstPack(t, bare)
			if err := os.Chmod(pack, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(pack, 16); err != nil {
				t.Fatal(err)
			}
			if err := engine.CommitExists(context.Background(), bare, fixture.secondCommit); err == nil {
				t.Fatal("truncated pack was accepted")
			}
		})
	}
}

func TestShallowRepositoryExactHeadRemainsReadable(t *testing.T) {
	fixture := createRepository(t, "sha1")
	shallow := filepath.Join(t.TempDir(), "shallow")
	runGit(t, fixture.root, "clone", "-q", "--depth=1", "file://"+fixture.root, shallow)
	ctx := context.Background()
	wantHead, err := (nativeAdapter{}).Head(ctx, shallow)
	if err != nil {
		t.Fatal(err)
	}
	gotHead, err := (goGitAdapter{}).Head(ctx, shallow)
	if err != nil {
		t.Fatal(err)
	}
	if gotHead != wantHead || gotHead != fixture.secondCommit {
		t.Fatalf("shallow HEAD disagreement: native=%s go-git=%s", wantHead, gotHead)
	}
	assertTreesEqual(t, ctx, nativeAdapter{}, goGitAdapter{}, shallow, fixture.secondCommit)
	if err := (nativeAdapter{}).CommitExists(ctx, shallow, fixture.firstCommit); err == nil {
		t.Fatal("native Git unexpectedly found omitted shallow parent")
	}
	if err := (goGitAdapter{}).CommitExists(ctx, shallow, fixture.firstCommit); err == nil {
		t.Fatal("go-git unexpectedly found omitted shallow parent")
	}
}

type rawTreeEntry struct {
	mode string
	name []byte
	oid  string
}

func rawTree(entries ...rawTreeEntry) []byte {
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].name, entries[j].name) < 0 })
	var output []byte
	for _, entry := range entries {
		oid, err := hex.DecodeString(entry.oid)
		if err != nil {
			panic(err)
		}
		output = append(output, entry.mode...)
		output = append(output, ' ')
		output = append(output, entry.name...)
		output = append(output, 0)
		output = append(output, oid...)
	}
	return output
}

func writeRawTree(t *testing.T, repository string, data []byte) string {
	t.Helper()
	return gitInput(t, repository, data, "hash-object", "--literally", "-t", "tree", "-w", "--stdin")
}

func gitInput(t *testing.T, repository string, input []byte, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	command.Env = testgit.Environment()
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

func firstPack(t *testing.T, bare string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(bare, "objects", "pack"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pack") {
			return filepath.Join(bare, "objects", "pack", entry.Name())
		}
	}
	t.Fatal(fmt.Errorf("repository contains no pack"))
	return ""
}
