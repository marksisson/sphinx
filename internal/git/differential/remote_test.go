package differential

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMirrorMaterializationMatchesNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	source := filepath.Join(t.TempDir(), "source.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, source)
	nativeClone := filepath.Join(t.TempDir(), "native.git")
	candidateClone := filepath.Join(t.TempDir(), "candidate.git")
	ctx := context.Background()
	if err := (nativeAdapter{}).CloneMirror(ctx, source, nativeClone); err != nil {
		t.Fatal(err)
	}
	if err := (goGitAdapter{}).CloneMirror(ctx, source, candidateClone); err != nil {
		t.Fatal(err)
	}

	for _, clone := range []string{nativeClone, candidateClone} {
		discovered, err := (goGitAdapter{}).Discover(ctx, clone)
		if err != nil {
			t.Fatal(err)
		}
		if !discovered.Bare {
			t.Fatalf("mirror clone %q is not bare", clone)
		}
		if _, err := os.Lstat(filepath.Join(clone, "objects", "info", "alternates")); !os.IsNotExist(err) {
			t.Fatalf("mirror clone %q contains object alternates", clone)
		}
	}
	for _, selector := range []string{"", "lightweight", "annotated"} {
		nativeCommit, err := (nativeAdapter{}).ResolveRemote(ctx, nativeClone, selector)
		if err != nil {
			t.Fatal(err)
		}
		candidateCommit, err := (goGitAdapter{}).ResolveRemote(ctx, candidateClone, selector)
		if err != nil {
			t.Fatal(err)
		}
		if candidateCommit != nativeCommit {
			t.Fatalf("mirror selector %q disagreement: native=%s go-git=%s", selector, nativeCommit, candidateCommit)
		}
	}
	nativeTree, err := (nativeAdapter{}).ListTree(ctx, nativeClone, fixture.secondCommit)
	if err != nil {
		t.Fatal(err)
	}
	candidateTree, err := (goGitAdapter{}).ListTree(ctx, candidateClone, fixture.secondCommit)
	if err != nil {
		t.Fatal(err)
	}
	sortTree(nativeTree)
	sortTree(candidateTree)
	if !reflect.DeepEqual(candidateTree, nativeTree) {
		t.Fatalf("mirror tree disagreement\nnative: %#v\ngo-git: %#v", nativeTree, candidateTree)
	}
}

func TestRemoteAdvertisementResolutionMatchesNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	runGit(t, fixture.root, "branch", "collision", fixture.firstCommit)
	runGit(t, fixture.root, "tag", "collision", fixture.secondCommit)
	bare := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, bare)

	ctx := context.Background()
	for _, test := range []struct {
		selector string
		want     string
	}{
		{"", fixture.secondCommit},
		{"lightweight", fixture.firstCommit},
		{"annotated", fixture.secondCommit},
	} {
		want, err := (nativeAdapter{}).ResolveRemote(ctx, bare, test.selector)
		if err != nil {
			t.Fatalf("native selector %q: %v", test.selector, err)
		}
		got, err := (goGitAdapter{}).ResolveRemote(ctx, bare, test.selector)
		if err != nil {
			t.Fatalf("go-git selector %q: %v", test.selector, err)
		}
		if want != test.want || got != want {
			t.Fatalf("selector %q disagreement: native=%s go-git=%s want=%s", test.selector, want, got, test.want)
		}
	}
	for _, selector := range []string{"collision", "missing"} {
		if _, err := (nativeAdapter{}).ResolveRemote(ctx, bare, selector); err == nil {
			t.Fatalf("native Git accepted selector %q", selector)
		}
		if _, err := (goGitAdapter{}).ResolveRemote(ctx, bare, selector); err == nil {
			t.Fatalf("go-git accepted selector %q", selector)
		}
	}
}
