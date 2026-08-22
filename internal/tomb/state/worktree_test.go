package state

import (
	"os"
	"path/filepath"
	"testing"

	gitresource "github.com/marksisson/sphinx/internal/git/resource"
)

func TestLoadWorktreeContentRejectsUnsupportedMetadata(t *testing.T) {
	bundle := newBundle(t, 120)
	defer bundle.signing.Destroy()
	content := signedContent(t, bundle, 1, "")
	root := writeContentTree(t, content)
	path := filepath.Join(root, ".tomb/extra.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWorktreeContent(root); err == nil {
		t.Fatal("unsupported metadata accepted")
	}
}
func TestLoadWorktreeContentReadsCompleteState(t *testing.T) {
	bundle := newBundle(t, 121)
	defer bundle.signing.Destroy()
	content := signedContent(t, bundle, 1, "")
	root := writeContentTree(t, content)
	loaded, err := LoadWorktreeContent(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(loaded); err != nil {
		t.Fatal(err)
	}
}
func writeContentTree(t *testing.T, content *gitresource.Content) string {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{".tomb/tomb.yaml": content.Manifest.Data, ".tomb/decree.yaml": content.Decree.Data, ".tomb/decree.yaml.sig": content.Signature.Data, ".tomb/rotations/.keep": {}}
	for _, blob := range content.Artifacts {
		files[blob.Path] = blob.Data
	}
	for _, blob := range content.Schemas {
		files[blob.Path] = blob.Data
	}
	for _, group := range content.Rotations {
		files[group.Transition.Path] = group.Transition.Data
		files[group.From.Path] = group.From.Data
		files[group.To.Path] = group.To.Data
	}
	for path, data := range files {
		filename := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
