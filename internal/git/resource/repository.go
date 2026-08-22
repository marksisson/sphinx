// Package resource materializes immutable Git object databases and reads
// exact committed blobs without creating a checkout.
package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marksisson/sphinx/internal/locator"
	"golang.org/x/sys/unix"
)

type Materializer struct {
	CacheRoot string
}

type Repository struct {
	gitDirectory string
	commit       string
	identity     string
}

type Blob struct {
	Path string
	Mode string
	OID  string
	Data []byte
}

func (b Blob) SHA256() [32]byte { return sha256.Sum256(b.Data) }

func (b Blob) SHA256Hex() string {
	digest := b.SHA256()
	return hex.EncodeToString(digest[:])
}

type TreeEntry struct {
	Path string
	Mode string
	Type string
	OID  string
}

// ResolveCommit resolves a ref, rev, or default branch without mutating a
// worktree. Ambiguous same-name branch/tag refs are rejected.
func ResolveCommit(ctx context.Context, reference locator.Locator) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if reference.Type == locator.TypePath && reference.Ref == "" && reference.Rev == "" {
		opened, err := openWorktreeRepository(reference.Path)
		if err != nil {
			return "", err
		}
		defer opened.close()
		head, err := opened.repository.Head()
		if err != nil {
			return "", err
		}
		commit, err := opened.repository.CommitObject(head.Hash())
		if err != nil {
			return "", err
		}
		return commit.Hash.String(), nil
	}
	if reference.Rev != "" {
		return reference.Rev, nil
	}
	return resolveRemoteCommit(ctx, reference.CloneURL(), reference.Ref)
}

func DefaultCacheRoot() (string, error) {
	root := os.Getenv("XDG_CACHE_HOME")
	if root == "" || !filepath.IsAbs(root) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		root = filepath.Join(home, ".cache")
	}
	return filepath.Join(root, "sphinx", "tombs"), nil
}

// Materialize installs or reuses one bare, immutable cache entry keyed by the
// canonical repository identity and approved commit.
func (m Materializer) Materialize(ctx context.Context, reference locator.Locator, approvedCommit string) (*Repository, error) {
	if !locator.IsFullRevision(approvedCommit) {
		return nil, fmt.Errorf("approved tomb commit is not a full lowercase Git commit ID")
	}
	if reference.Rev != "" && reference.Rev != approvedCommit {
		return nil, fmt.Errorf("tomb rev selector does not match approved commit")
	}
	if reference.Type == locator.TypePath {
		source, err := openWorktreeRepository(reference.Path)
		if err != nil {
			return nil, fmt.Errorf("open local tomb source: %w", err)
		}
		source.close()
	}
	cacheRoot, err := filepath.Abs(m.CacheRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve tomb cache: %w", err)
	}
	if err := secureCacheRoot(cacheRoot); err != nil {
		return nil, err
	}
	identity := reference.Base()
	digest := sha256.Sum256([]byte(identity + "\x00" + approvedCommit))
	key := hex.EncodeToString(digest[:])
	entry := filepath.Join(cacheRoot, "objects", key+".git")
	lockPath := filepath.Join(cacheRoot, "locks", key+".lock")
	for _, directory := range []string{filepath.Dir(entry), filepath.Dir(lockPath), filepath.Join(cacheRoot, "candidates")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create tomb cache directory: %w", err)
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("tomb cache component %s is not a non-symlink directory", directory)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("secure tomb cache directory: %w", err)
		}
	}
	lockFD, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open non-symlink tomb cache lock: %w", err)
	}
	lock := os.NewFile(uintptr(lockFD), lockPath)
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock tomb cache: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck

	repository := &Repository{gitDirectory: entry, commit: approvedCommit, identity: identity}
	if _, err := os.Lstat(entry); err == nil {
		if err := repository.validate(ctx); err == nil {
			return repository, nil
		}
		if err := os.RemoveAll(entry); err != nil {
			return nil, fmt.Errorf("evict corrupt tomb cache entry: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect tomb cache entry: %w", err)
	}

	candidate, err := os.MkdirTemp(filepath.Join(cacheRoot, "candidates"), key+"-")
	if err != nil {
		return nil, fmt.Errorf("create tomb cache candidate: %w", err)
	}
	defer os.RemoveAll(candidate)
	if err := cloneMirror(ctx, reference.CloneURL(), candidate); err != nil {
		return nil, fmt.Errorf("materialize tomb repository: %w", err)
	}
	candidateRepository := &Repository{gitDirectory: candidate, commit: approvedCommit, identity: identity}
	if err := candidateRepository.validate(ctx); err != nil {
		return nil, fmt.Errorf("candidate tomb does not contain approved commit: %w", err)
	}
	if err := syncTree(candidate); err != nil {
		return nil, fmt.Errorf("sync tomb cache candidate: %w", err)
	}
	if err := os.Rename(candidate, entry); err != nil {
		return nil, fmt.Errorf("promote tomb cache candidate: %w", err)
	}
	if err := syncDirectory(filepath.Dir(entry)); err != nil {
		return nil, fmt.Errorf("sync tomb cache promotion: %w", err)
	}
	return repository, repository.validate(ctx)
}

func secureCacheRoot(root string) error {
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("tomb cache root must be a non-symlink directory")
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("create tomb cache root: %w", err)
		}
	} else {
		return fmt.Errorf("inspect tomb cache root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("secure tomb cache root: %w", err)
	}
	return nil
}

func (r *Repository) validate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(r.gitDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache entry is not a non-symlink Git directory")
	}
	opened, err := openBareRepository(r.gitDirectory)
	if err != nil {
		return err
	}
	defer opened.close()
	commit, err := repositoryCommit(opened.repository, r.commit)
	if err != nil {
		return err
	}
	if commit.Hash.String() != r.commit {
		return fmt.Errorf("cache commit resolved to unexpected object")
	}
	return nil
}

func (r *Repository) Commit() string   { return r.commit }
func (r *Repository) Identity() string { return r.identity }

func (r *Repository) ReadBlob(ctx context.Context, path string) (Blob, error) {
	if err := ctx.Err(); err != nil {
		return Blob{}, err
	}
	if path == "" || strings.ContainsRune(path, '\x00') {
		return Blob{}, fmt.Errorf("Git blob path is empty or invalid")
	}
	opened, err := openBareRepository(r.gitDirectory)
	if err != nil {
		return Blob{}, err
	}
	defer opened.close()
	commit, err := repositoryCommit(opened.repository, r.commit)
	if err != nil {
		return Blob{}, err
	}
	root, err := commit.Tree()
	if err != nil {
		return Blob{}, err
	}
	entry, err := exactTreeEntry(opened.repository, root, path)
	if err != nil {
		return Blob{}, fmt.Errorf("committed path %q is missing or ambiguous: %w", path, err)
	}
	mode := formatMode(entry.Mode)
	if entry.Mode != 0o100644 && entry.Mode != 0o100755 {
		return Blob{}, fmt.Errorf("committed path %q must be a regular Git blob", path)
	}
	objectBlob, err := opened.repository.BlobObject(entry.Hash)
	if err != nil {
		return Blob{}, err
	}
	reader, err := objectBlob.Reader()
	if err != nil {
		return Blob{}, err
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return Blob{}, readErr
	}
	if closeErr != nil {
		return Blob{}, closeErr
	}
	blob := Blob{Path: path, Mode: mode, OID: entry.Hash.String(), Data: data}
	if err := r.ValidateManagedBlob(ctx, blob); err != nil {
		return Blob{}, err
	}
	return blob, nil
}

func (r *Repository) ListTree(ctx context.Context) ([]TreeEntry, error) {
	opened, err := openBareRepository(r.gitDirectory)
	if err != nil {
		return nil, err
	}
	defer opened.close()
	return listCommitTree(ctx, opened.repository, r.commit)
}

func (r *Repository) ValidateManagedBlob(ctx context.Context, blob Blob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if bytes.HasPrefix(blob.Data, []byte("version https://git-lfs.github.com/spec/v1\n")) {
		return fmt.Errorf("managed path %q is a Git LFS pointer", blob.Path)
	}
	opened, err := openBareRepository(r.gitDirectory)
	if err != nil {
		return err
	}
	defer opened.close()
	attributeNames := []string{"filter", "working-tree-encoding", "text", "eol"}
	attributes, err := committedAttributes(opened.repository, r.commit, blob.Path, attributeNames)
	if err != nil {
		return err
	}
	for _, attribute := range attributeNames {
		value := attributes[attribute]
		safe := value == "unspecified" || (attribute == "text" && value == "unset")
		if !safe {
			return fmt.Errorf("managed path %q has unsafe Git attribute %s=%s", blob.Path, attribute, value)
		}
	}
	return nil
}

func (r *Repository) IsDescendant(ctx context.Context, ancestor, descendant string) (bool, error) {
	if !locator.IsFullRevision(ancestor) || !locator.IsFullRevision(descendant) {
		return false, fmt.Errorf("descendant check requires full commit IDs")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	opened, err := openBareRepository(r.gitDirectory)
	if err != nil {
		return false, err
	}
	defer opened.close()
	ancestorCommit, err := repositoryCommit(opened.repository, ancestor)
	if err != nil {
		return false, err
	}
	descendantCommit, err := repositoryCommit(opened.repository, descendant)
	if err != nil {
		return false, err
	}
	return ancestorCommit.IsAncestor(descendantCommit)
}

func syncTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		err = file.Sync()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
