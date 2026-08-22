package safefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicCreatesAndReplacesWithoutSizeCap(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "config.yaml")
	first := bytes.Repeat([]byte("x"), 2<<20)
	if err := WriteAtomic(filename, first, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(filename, []byte("replacement"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement" {
		t.Fatalf("file contains %q", got)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("replacement mode = %#o, want 0600", got)
	}
}

func TestWriteAtomicRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomicWithin(root, filepath.Join("linked", "artifact.yaml"), []byte("secret"), 0o600); err == nil {
		t.Fatal("WriteAtomic unexpectedly followed a symlink")
	}
}

func TestWriteAtomicRejectsNonRegularDestination(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "destination")
	if err := os.Mkdir(filename, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(filename, nil, 0o600); err == nil {
		t.Fatal("WriteAtomic unexpectedly replaced a directory")
	}
}
