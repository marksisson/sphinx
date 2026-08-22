package locator

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const revision = "a3a3dda3bacf61e8a39258a0ed9c924eeca8e293"

func TestParseRemoteReferences(t *testing.T) {
	tests := []struct {
		input string
		want  Locator
	}{
		{"github:example/secrets-tomb", Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb"}},
		{"github:example/secrets-tomb?ref=release%2F2026", Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Ref: "release/2026"}},
		{"github:example/secrets-tomb?rev=" + revision, Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Rev: revision}},
		{"git+https://git.example.com/example/secrets.git?ref=main", Locator{Type: TypeGit, URL: "https://git.example.com/example/secrets.git", Ref: "main"}},
		{"git+ssh://git@git.example.com/example/secrets.git?rev=" + revision, Locator{Type: TypeGit, URL: "ssh://git@git.example.com/example/secrets.git", Rev: revision}},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := ParseAt(context.Background(), test.input, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ParseAt() = %#v, want %#v", got, test.want)
			}
			if reparsed, err := ParseAt(context.Background(), got.String(), t.TempDir()); err != nil || reparsed != got {
				t.Fatalf("canonical round trip = %#v, %v", reparsed, err)
			}
		})
	}
}

func TestParsePathRequiresExactGitWorktreeRoot(t *testing.T) {
	root := newRepository(t)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := ParseAt(context.Background(), "path:.", root)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(root)
	if got.Type != TypePath || got.Path != resolved || got.String() != "path:"+resolved {
		t.Fatalf("path reference = %#v", got)
	}
	if _, err := ParseAt(context.Background(), "path:child", root); err == nil {
		t.Fatal("ParseAt unexpectedly accepted a worktree subdirectory")
	}
	if _, err := ParseAt(context.Background(), "path:.", t.TempDir()); err == nil {
		t.Fatal("ParseAt unexpectedly accepted a non-Git directory")
	}
	link := filepath.Join(t.TempDir(), "linked-worktree")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAt(context.Background(), "path:"+link, root); err == nil {
		t.Fatal("ParseAt unexpectedly traversed a worktree symlink")
	}
}

func TestParseRejectsUnsafeAndUnsupportedReferences(t *testing.T) {
	tests := []string{
		"", " relative", "./secrets", "github:owner", "github:owner/repo/main",
		"github:owner/repo?dir=secrets", "github:owner/repo?file=artifact.yaml",
		"github:owner/repo?ref=main&ref=other", "github:owner/repo?ref=main&rev=" + revision,
		"github:owner/repo#fragment", "github:owner%2frepo",
		"git+file:///tmp/tomb", "git+https://user:secret@example.com/tomb",
		"git+ssh://root@example.com/tomb", "https://example.com/tomb.tar.gz",
		"git+https://example.com/tomb?rev=abc", "git+https://example.com/tomb?ref=../main",
	}
	for _, input := range tests {
		if _, err := ParseAt(context.Background(), input, t.TempDir()); err == nil {
			t.Errorf("ParseAt(%q) unexpectedly succeeded", input)
		}
	}
}

func TestFormattingAndDefaultName(t *testing.T) {
	parsed, err := ParseAt(context.Background(), "github:example/secrets.git?ref=release%2F2026", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Base() != "github:example/secrets" || parsed.String() != "github:example/secrets?ref=release%2F2026" {
		t.Fatalf("canonical forms = %q, %q", parsed.Base(), parsed.String())
	}
	if parsed.CloneURL() != "https://github.com/example/secrets.git" || parsed.DefaultName() != "secrets" {
		t.Fatalf("derived forms = %q, %q", parsed.CloneURL(), parsed.DefaultName())
	}
}

func newRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
