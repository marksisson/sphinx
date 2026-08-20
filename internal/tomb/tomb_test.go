package tomb

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input    string
		location string
		remote   bool
		valid    bool
	}{
		{"./secrets", "./secrets", false, true},
		{"github:example/secrets-tomb", "https://github.com/example/secrets-tomb.git", true, true},
		{"git+https://github.com/example/secrets-tomb.git", "https://github.com/example/secrets-tomb.git", true, true},
		{"git+ssh://git@github.com/example/secrets-tomb.git", "ssh://git@github.com/example/secrets-tomb.git", true, true},
		{"https://github.com/example/secrets-tomb", "", false, false},
		{"github:missing-owner", "", false, false},
		{"git+file:///tmp/tomb", "", false, false},
		{"", "", false, false},
	}
	for _, test := range tests {
		source, err := Parse(test.input)
		if (err == nil) != test.valid {
			t.Errorf("Parse(%q) error = %v, valid=%v", test.input, err, test.valid)
			continue
		}
		if err == nil && (source.location != test.location || source.remote != test.remote) {
			t.Errorf("Parse(%q) = %#v", test.input, source)
		}
	}
}

func TestMaterializeGitTomb(t *testing.T) {
	repository := t.TempDir()
	runTestGit(t, repository, "init", "--initial-branch=main")
	runTestGit(t, repository, "config", "user.name", "Sphinx Test")
	runTestGit(t, repository, "config", "user.email", "sphinx@example.invalid")
	if err := os.MkdirAll(filepath.Join(repository, "secrets", "example"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "secrets", "example", "relic.yaml"), []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, repository, "add", ".")
	runTestGit(t, repository, "commit", "-m", "add test Relic")

	// A local file URL is intentionally not accepted by Parse, but constructing
	// a Source directly allows an entirely offline materialization test.
	source := Source{location: "file://" + repository, remote: true}
	materialized, err := source.Materialize(context.Background(), filepath.Join(t.TempDir(), "cache"), "main", "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if !materialized.Remote || materialized.Revision == "" {
		t.Fatalf("Materialize() = %#v", materialized)
	}
	if _, err := os.Stat(filepath.Join(materialized.Root, "example", "relic.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsUnsafeReferenceAndSubdirectory(t *testing.T) {
	source := Source{location: "https://github.com/example/tomb.git", remote: true}
	if _, err := source.Materialize(context.Background(), t.TempDir(), "--upload-pack=evil", "."); err == nil {
		t.Fatal("unsafe Git reference was accepted")
	}
	if _, err := source.Materialize(context.Background(), t.TempDir(), "main", "../escape"); err == nil {
		t.Fatal("escaping subdirectory was accepted")
	}
}

func runTestGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	arguments = append([]string{"-C", directory}, arguments...)
	command := exec.Command("git", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
}
