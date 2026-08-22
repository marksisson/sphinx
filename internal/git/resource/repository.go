// Package resource materializes immutable Git object databases and reads
// exact committed blobs without creating a checkout.
package resource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	gitenv "github.com/marksisson/sphinx/internal/git/env"
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
	if reference.Type == locator.TypePath && reference.Ref == "" && reference.Rev == "" {
		output, err := git(ctx, "", "-C", reference.Path, "rev-parse", "--verify", "HEAD^{commit}")
		if err != nil {
			return "", err
		}
		commit := strings.TrimSpace(string(output))
		if !locator.IsFullRevision(commit) {
			return "", fmt.Errorf("local tomb HEAD did not resolve to a full lowercase Git commit ID")
		}
		return commit, nil
	}
	if reference.Rev != "" {
		return reference.Rev, nil
	}
	selector := reference.Ref
	patterns := []string{"HEAD"}
	if selector != "" {
		patterns = []string{"refs/heads/" + selector, "refs/tags/" + selector, "refs/tags/" + selector + "^{}"}
	}
	arguments := append([]string{"ls-remote", "--"}, reference.CloneURL())
	arguments = append(arguments, patterns...)
	output, err := git(ctx, "", arguments...)
	if err != nil {
		return "", err
	}
	var head, tag, peeled string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch {
		case fields[1] == "HEAD" || strings.HasPrefix(fields[1], "refs/heads/"):
			head = fields[0]
		case strings.HasSuffix(fields[1], "^{}"):
			peeled = fields[0]
		case strings.HasPrefix(fields[1], "refs/tags/"):
			tag = fields[0]
		}
	}
	if selector != "" && head != "" && tag != "" {
		return "", fmt.Errorf("Git ref %q is ambiguous between a branch and tag", selector)
	}
	commit := head
	if commit == "" {
		commit = peeled
	}
	if commit == "" {
		commit = tag
	}
	if !locator.IsFullRevision(commit) {
		return "", fmt.Errorf("Git selector did not resolve to a full commit ID")
	}
	return commit, nil
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
	if err := os.Remove(candidate); err != nil {
		return nil, fmt.Errorf("prepare tomb cache candidate: %w", err)
	}
	defer os.RemoveAll(candidate)
	if _, err := git(ctx, "", "clone", "--mirror", "--no-hardlinks", "--", reference.CloneURL(), candidate); err != nil {
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
	info, err := os.Lstat(r.gitDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache entry is not a non-symlink Git directory")
	}
	actual, err := git(ctx, r.gitDirectory, "rev-parse", "--verify", r.commit+"^{commit}")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(actual)) != r.commit {
		return fmt.Errorf("cache commit resolved to unexpected object")
	}
	return nil
}

func (r *Repository) Commit() string   { return r.commit }
func (r *Repository) Identity() string { return r.identity }

func (r *Repository) ReadBlob(ctx context.Context, path string) (Blob, error) {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return Blob{}, fmt.Errorf("Git blob path is empty or invalid")
	}
	output, err := git(ctx, r.gitDirectory, "ls-tree", "-z", "--full-tree", r.commit, "--", ":(literal)"+path)
	if err != nil {
		return Blob{}, err
	}
	entries, err := parseTree(output)
	if err != nil {
		return Blob{}, err
	}
	if len(entries) != 1 || entries[0].Path != path {
		return Blob{}, fmt.Errorf("committed path %q is missing or ambiguous", path)
	}
	entry := entries[0]
	if entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") {
		return Blob{}, fmt.Errorf("committed path %q must be a regular Git blob", path)
	}
	data, err := git(ctx, r.gitDirectory, "cat-file", "blob", entry.OID)
	if err != nil {
		return Blob{}, err
	}
	blob := Blob{Path: path, Mode: entry.Mode, OID: entry.OID, Data: data}
	if err := r.ValidateManagedBlob(ctx, blob); err != nil {
		return Blob{}, err
	}
	return blob, nil
}

func (r *Repository) ListTree(ctx context.Context) ([]TreeEntry, error) {
	output, err := git(ctx, r.gitDirectory, "ls-tree", "-r", "-z", "--full-tree", r.commit)
	if err != nil {
		return nil, err
	}
	return parseTree(output)
}

func parseTree(output []byte) ([]TreeEntry, error) {
	records := bytes.Split(output, []byte{0})
	entries := make([]TreeEntry, 0, len(records))
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		header, name, found := bytes.Cut(record, []byte{'\t'})
		parts := bytes.Fields(header)
		if !found || len(parts) != 3 {
			return nil, fmt.Errorf("malformed Git tree entry")
		}
		entries = append(entries, TreeEntry{Mode: string(parts[0]), Type: string(parts[1]), OID: string(parts[2]), Path: string(name)})
	}
	return entries, nil
}

func (r *Repository) ValidateManagedBlob(ctx context.Context, blob Blob) error {
	if bytes.HasPrefix(blob.Data, []byte("version https://git-lfs.github.com/spec/v1\n")) {
		return fmt.Errorf("managed path %q is a Git LFS pointer", blob.Path)
	}
	output, err := git(ctx, r.gitDirectory, "check-attr", "-z", "--source="+r.commit,
		"filter", "working-tree-encoding", "text", "eol", "--", blob.Path)
	if err != nil {
		return err
	}
	parts := bytes.Split(output, []byte{0})
	for index := 0; index+2 < len(parts); index += 3 {
		attribute, value := string(parts[index+1]), string(parts[index+2])
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
	command := exec.CommandContext(ctx, "git", "--git-dir", r.gitDirectory, "merge-base", "--is-ancestor", ancestor, descendant)
	command.Env = gitEnvironment()
	err := command.Run()
	if err == nil {
		return true, nil
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("check Git ancestry: %w", err)
}

func git(ctx context.Context, gitDirectory string, arguments ...string) ([]byte, error) {
	if gitDirectory != "" {
		arguments = append([]string{"--git-dir", gitDirectory}, arguments...)
	}
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Env = gitEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", arguments[0], message)
	}
	return output, nil
}

func gitEnvironment() []string { return gitenv.Environment() }

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
