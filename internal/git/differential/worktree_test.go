package differential

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWorktreeStatusAndIndexMatchNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	root := fixture.root

	writeFixture(t, root, "artifact.yaml", "staged change\n", 0o600)
	runGit(t, root, "add", "--", "artifact.yaml")
	writeFixture(t, root, "nested/deeper/value.txt", "unstaged change\n", 0o600)
	if err := os.Remove(filepath.Join(root, "new.txt")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "untracked.txt", "untracked\n", 0o600)
	if err := os.Chmod(filepath.Join(root, "executable.sh"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	nativeStatus, err := (nativeAdapter{}).Status(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	beforeCandidate := snapshotAdministrativeFiles(t, root)
	candidateStatus, err := (goGitAdapter{}).Status(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(candidateStatus, nativeStatus) {
		t.Fatalf("status disagreement\nnative: %#v\ngo-git: %#v", nativeStatus, candidateStatus)
	}
	if afterCandidate := snapshotAdministrativeFiles(t, root); !reflect.DeepEqual(afterCandidate, beforeCandidate) {
		t.Fatal("go-git status changed Git administrative bytes")
	}

	nativeIndex, err := (nativeAdapter{}).Index(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	candidateIndex, err := (goGitAdapter{}).Index(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(candidateIndex, nativeIndex) {
		t.Fatalf("index disagreement\nnative: %#v\ngo-git: %#v", nativeIndex, candidateIndex)
	}
	for _, entry := range candidateIndex {
		if entry.Stage != 0 {
			t.Fatalf("ordinary index entry %q decoded as stage %d, want raw stage 0", entry.Path, entry.Stage)
		}
	}
}

func TestUnsupportedIndexVersionsAreConservativelyRejected(t *testing.T) {
	for _, version := range []string{"3", "4"} {
		t.Run("v"+version, func(t *testing.T) {
			fixture := createRepository(t, "sha1")
			if version == "3" {
				runGit(t, fixture.root, "update-index", "--skip-worktree", "artifact.yaml")
			}
			runGit(t, fixture.root, "update-index", "--index-version="+version)
			if _, err := (nativeAdapter{}).Index(context.Background(), fixture.root); err != nil {
				t.Fatalf("native Git rejected index v%s: %v", version, err)
			}
			if _, err := (goGitAdapter{}).Index(context.Background(), fixture.root); err == nil {
				t.Fatalf("go-git adapter accepted unsupported index v%s", version)
			}
		})
	}
}

func TestConflictedIndexRawStagesMatchNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	root := fixture.root

	runGit(t, root, "checkout", "-q", "-b", "other", fixture.firstCommit)
	writeFixture(t, root, "artifact.yaml", "other branch\n", 0o600)
	runGit(t, root, "add", "artifact.yaml")
	runGit(t, root, "commit", "-q", "-m", "other")
	other := gitText(t, root, "rev-parse", "HEAD")

	runGit(t, root, "checkout", "-q", "--detach", fixture.firstCommit)
	writeFixture(t, root, "artifact.yaml", "current branch\n", 0o600)
	runGit(t, root, "add", "artifact.yaml")
	runGit(t, root, "commit", "-q", "-m", "current")
	if output, err := nativeGit(context.Background(), root, "merge", "--no-commit", "--no-ff", other); err == nil {
		t.Fatalf("merge unexpectedly succeeded without conflict: %s", output)
	}

	ctx := context.Background()
	nativeIndex, err := (nativeAdapter{}).Index(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	beforeCandidate := snapshotAdministrativeFiles(t, root)
	candidateIndex, err := (goGitAdapter{}).Index(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(candidateIndex, nativeIndex) {
		t.Fatalf("conflicted index disagreement\nnative: %#v\ngo-git: %#v", nativeIndex, candidateIndex)
	}
	stages := make(map[int]bool)
	for _, entry := range candidateIndex {
		if entry.Path == "artifact.yaml" {
			stages[entry.Stage] = true
		}
	}
	if !reflect.DeepEqual(stages, map[int]bool{1: true, 2: true, 3: true}) {
		t.Fatalf("conflict stages = %#v, want stages 1/2/3", stages)
	}
	if afterCandidate := snapshotAdministrativeFiles(t, root); !reflect.DeepEqual(afterCandidate, beforeCandidate) {
		t.Fatal("go-git index read changed Git administrative bytes")
	}
}
