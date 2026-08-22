package differential

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsafeExternalObjectSourcesAreConservativelyRejected(t *testing.T) {
	t.Run("alternates", func(t *testing.T) {
		fixture := createRepository(t, "sha1")
		external := createRepository(t, "sha1")
		alternates := filepath.Join(fixture.root, ".git", "objects", "info", "alternates")
		if err := os.WriteFile(alternates, []byte(filepath.Join(external.root, ".git", "objects")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertNativeAcceptsCandidateRejects(t, fixture.root)
	})

	t.Run("replacement refs", func(t *testing.T) {
		fixture := createRepository(t, "sha1")
		runGit(t, fixture.root, "replace", fixture.firstCommit, fixture.secondCommit)
		assertNativeAcceptsCandidateRejects(t, fixture.root)
	})

	t.Run("promisor remote", func(t *testing.T) {
		fixture := createRepository(t, "sha1")
		runGit(t, fixture.root, "config", "remote.origin.url", "https://example.invalid/repository.git")
		runGit(t, fixture.root, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
		runGit(t, fixture.root, "config", "remote.origin.promisor", "true")
		runGit(t, fixture.root, "config", "remote.origin.partialclonefilter", "blob:none")
		assertNativeAcceptsCandidateRejects(t, fixture.root)
	})
}

func TestUnknownRepositoryExtensionFailsClosed(t *testing.T) {
	fixture := createRepository(t, "sha1")
	runGit(t, fixture.root, "config", "core.repositoryformatversion", "1")
	runGit(t, fixture.root, "config", "extensions.sphinx-unknown", "true")
	if _, err := (nativeAdapter{}).Head(context.Background(), fixture.root); err == nil {
		t.Fatal("native Git accepted an unknown repository extension")
	}
	if _, err := (goGitAdapter{}).Head(context.Background(), fixture.root); err == nil {
		t.Fatal("go-git accepted an unknown repository extension")
	}
}

func assertNativeAcceptsCandidateRejects(t *testing.T, repository string) {
	t.Helper()
	if _, err := (nativeAdapter{}).Head(context.Background(), repository); err != nil {
		t.Fatalf("native Git rejected fixture outside narrowed contract: %v", err)
	}
	if _, err := (goGitAdapter{}).Head(context.Background(), repository); err == nil {
		t.Fatal("go-git adapter accepted repository outside narrowed contract")
	}
}
