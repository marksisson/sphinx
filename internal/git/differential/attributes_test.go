package differential

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAttributeEvaluationMatchesNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	root := fixture.root
	writeFixture(t, root, ".gitattributes", "[attr]sphinx-safe -filter -text\n*.yaml text eol=lf filter=lfs\n*.safe sphinx-safe\nnested/** custom=root\n", 0o600)
	writeFixture(t, root, "nested/.gitattributes", "*.txt -text !eol filter=custom\ndeep/*.txt working-tree-encoding=UTF-16\n", 0o600)
	writeFixture(t, root, "root.safe", "safe\n", 0o600)
	runGit(t, root, "add", "--all")
	runGit(t, root, "commit", "-q", "-m", "attributes")
	commit := gitText(t, root, "rev-parse", "HEAD")

	// Worktree attributes intentionally disagree with the committed source.
	writeFixture(t, root, ".gitattributes", "[attr]sphinx-safe -filter -text\n*.yaml -text !eol filter=worktree\n*.safe sphinx-safe\nnested/** custom=worktree-root\n", 0o600)
	informationDirectory := filepath.Join(root, ".git", "info")
	if err := os.MkdirAll(informationDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(informationDirectory, "attributes"), []byte("artifact.yaml -filter custom=info\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	attributes := []string{"filter", "working-tree-encoding", "text", "eol", "custom"}
	ctx := context.Background()
	for _, source := range []string{"", commit} {
		for _, path := range []string{"artifact.yaml", "nested/deeper/value.txt", "root.safe", "literal/[abc]*?.txt"} {
			want, err := (nativeAdapter{}).Attributes(ctx, root, source, path, attributes)
			if err != nil {
				t.Fatalf("native attributes source=%q path=%q: %v", source, path, err)
			}
			got, err := (goGitAdapter{}).Attributes(ctx, root, source, path, attributes)
			if err != nil {
				t.Fatalf("go-git attributes source=%q path=%q: %v", source, path, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("attribute disagreement source=%q path=%q\nnative: %#v\ngo-git: %#v", source, path, want, got)
			}
		}
	}
}

func TestMalformedNestedMacroIsConservativelyRejected(t *testing.T) {
	fixture := createRepository(t, "sha1")
	writeFixture(t, fixture.root, "nested/.gitattributes", "[attr]nested-macro -text\n", 0o600)
	if _, err := (goGitAdapter{}).Attributes(context.Background(), fixture.root, "", "nested/deeper/value.txt", []string{"text"}); err == nil {
		t.Fatal("go-git adapter accepted a nested attribute macro definition")
	}
}
