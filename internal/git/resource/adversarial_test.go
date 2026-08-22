package resource

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marksisson/sphinx/internal/locator"
)

func TestMaterializeRejectsLocalSourceAlternates(t *testing.T) {
	root, commit := createTomb(t)
	alternates := filepath.Join(root, ".git", "objects", "info", "alternates")
	if err := os.WriteFile(alternates, []byte(filepath.Join(root, ".git", "objects")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reference := locator.Locator{Type: locator.TypePath, Path: root}
	if _, err := (Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, commit); err == nil {
		t.Fatal("Materialize unexpectedly accepted a local object alternate")
	}
}

func TestValidateContentRejectsSubmoduleAndSymlinkManagedPaths(t *testing.T) {
	t.Run("submodule artifact", func(t *testing.T) {
		root, commit := createTomb(t)
		runGit(t, root, "update-index", "--add", "--cacheinfo", "160000,"+commit+",submodule/artifact.yaml")
		runGit(t, root, "commit", "--quiet", "-m", "submodule artifact")
		assertContentRejected(t, root)
	})
	t.Run("symlink schema", func(t *testing.T) {
		root, _ := createTomb(t)
		filename := filepath.Join(root, ".tomb", "schemas", "linked", "v1.yaml")
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../api-key/v1.yaml", filename); err != nil {
			t.Fatal(err)
		}
		runGit(t, root, "add", ".tomb/schemas/linked/v1.yaml")
		runGit(t, root, "commit", "--quiet", "-m", "symlink schema")
		assertContentRejected(t, root)
	})
}

func assertContentRejected(t *testing.T, root string) {
	t.Helper()
	commit := gitText(t, root, "rev-parse", "HEAD")
	reference, err := locator.ParseAt(context.Background(), "path:"+root, root)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := (Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, commit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ValidateContent(context.Background()); err == nil {
		t.Fatal("ValidateContent unexpectedly accepted an unsafe Git entry")
	}
}
