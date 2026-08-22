// Package repository provides shared, read-only Git repository discovery.
package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v6/osfs"
	gitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/storage/filesystem"
	xworktree "github.com/go-git/go-git/v6/x/plumbing/worktree"
	gogitruntime "github.com/marksisson/sphinx/internal/git/runtime"
)

const administrativeFileLimit = 1024

// Worktree identifies one exact non-bare worktree and its administrative
// directories. All paths are absolute, symlink-resolved, and canonical.
type Worktree struct {
	Root      string
	GitDir    string
	CommonDir string
}

// DiscoverWorktree finds the nearest enclosing native-Git worktree. A .git
// entry encountered during ascent is authoritative: malformed metadata fails
// closed instead of being skipped in favor of an outer repository.
func DiscoverWorktree(ctx context.Context, start string) (Worktree, error) {
	if err := ctx.Err(); err != nil {
		return Worktree{}, err
	}
	absolute, err := filepath.Abs(start)
	if err != nil {
		return Worktree{}, fmt.Errorf("resolve Git discovery start: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Worktree{}, fmt.Errorf("resolve Git discovery start without symlinks: %w", err)
	}
	information, err := os.Stat(resolved)
	if err != nil {
		return Worktree{}, err
	}
	if !information.IsDir() {
		resolved = filepath.Dir(resolved)
	}
	for candidate := filepath.Clean(resolved); ; candidate = filepath.Dir(candidate) {
		if err := ctx.Err(); err != nil {
			return Worktree{}, err
		}
		dotGit := filepath.Join(candidate, ".git")
		if _, err := os.Lstat(dotGit); err == nil {
			return openDiscoveredWorktree(candidate, dotGit)
		} else if !errors.Is(err, os.ErrNotExist) {
			return Worktree{}, fmt.Errorf("inspect Git metadata: %w", err)
		}
		bare, err := isBareRepositoryRoot(candidate)
		if err != nil {
			return Worktree{}, err
		}
		if bare {
			return Worktree{}, fmt.Errorf("bare Git repositories are not worktrees")
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			break
		}
	}
	return Worktree{}, fmt.Errorf("no enclosing non-bare Git worktree")
}

// OpenWorktree requires path to name the exact worktree root.
func OpenWorktree(ctx context.Context, path string) (Worktree, error) {
	discovered, err := DiscoverWorktree(ctx, path)
	if err != nil {
		return Worktree{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Worktree{}, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Worktree{}, err
	}
	if filepath.Clean(resolved) != discovered.Root {
		return Worktree{}, fmt.Errorf("path must name the exact Git worktree root")
	}
	return discovered, nil
}

func isBareRepositoryRoot(path string) (bool, error) {
	objects, objectsErr := os.Lstat(filepath.Join(path, "objects"))
	head, headErr := os.Lstat(filepath.Join(path, "HEAD"))
	configuration, configErr := os.Lstat(filepath.Join(path, "config"))
	if errors.Is(objectsErr, os.ErrNotExist) || errors.Is(headErr, os.ErrNotExist) || errors.Is(configErr, os.ErrNotExist) {
		return false, nil
	}
	if objectsErr != nil || headErr != nil || configErr != nil {
		return false, fmt.Errorf("inspect possible bare Git repository")
	}
	if !objects.IsDir() || objects.Mode()&os.ModeSymlink != 0 || !head.Mode().IsRegular() || head.Mode()&os.ModeSymlink != 0 || !configuration.Mode().IsRegular() || configuration.Mode()&os.ModeSymlink != 0 {
		return false, nil
	}
	file, err := os.Open(filepath.Join(path, "config"))
	if err != nil {
		return false, err
	}
	parsed, parseErr := gitconfig.ReadConfig(file)
	closeErr := file.Close()
	if parseErr != nil {
		return false, parseErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	return parsed.Core.IsBare, nil
}

func openDiscoveredWorktree(root, dotGit string) (Worktree, error) {
	information, err := os.Lstat(dotGit)
	if err != nil {
		return Worktree{}, err
	}
	gitDirectory := dotGit
	if !information.IsDir() {
		if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return Worktree{}, fmt.Errorf(".git metadata must be a directory or non-symlink regular file")
		}
		value, err := readAdministrativeLine(dotGit, "gitdir: ")
		if err != nil {
			return Worktree{}, err
		}
		gitDirectory = value
		if !filepath.IsAbs(gitDirectory) {
			gitDirectory = filepath.Join(root, gitDirectory)
		}
	}
	gitDirectory, err = canonicalDirectory(gitDirectory, "Git administrative directory")
	if err != nil {
		return Worktree{}, err
	}
	commonDirectory := gitDirectory
	commonPath := filepath.Join(gitDirectory, "commondir")
	if _, err := os.Lstat(commonPath); err == nil {
		value, err := readAdministrativeLine(commonPath, "")
		if err != nil {
			return Worktree{}, err
		}
		commonDirectory = value
		if !filepath.IsAbs(commonDirectory) {
			commonDirectory = filepath.Join(gitDirectory, commonDirectory)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Worktree{}, err
	}
	commonDirectory, err = canonicalDirectory(commonDirectory, "Git common directory")
	if err != nil {
		return Worktree{}, err
	}
	root, err = canonicalDirectory(root, "Git worktree root")
	if err != nil {
		return Worktree{}, err
	}
	if err := validateWithGoGit(root, commonDirectory); err != nil {
		return Worktree{}, fmt.Errorf("open Git worktree: %w", err)
	}
	return Worktree{Root: root, GitDir: gitDirectory, CommonDir: commonDirectory}, nil
}

func readAdministrativeLine(filename, prefix string) (string, error) {
	information, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 || information.Size() > administrativeFileLimit {
		return "", fmt.Errorf("Git administrative metadata is not a bounded non-symlink regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, administrativeFileLimit+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) == 0 || len(data) > administrativeFileLimit || bytes.IndexByte(data, 0) >= 0 {
		return "", fmt.Errorf("malformed Git administrative metadata")
	}
	line := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(line, "\r\n") || !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("malformed Git administrative metadata")
	}
	value := strings.TrimPrefix(line, prefix)
	if value == "" || value != strings.TrimSpace(value) {
		return "", fmt.Errorf("malformed Git administrative metadata")
	}
	return value, nil
}

func canonicalDirectory(path, description string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", description, err)
	}
	information, err := os.Lstat(resolved)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a non-symlink directory", description)
	}
	return filepath.Clean(resolved), nil
}

func validateWithGoGit(root, commonDirectory string) error {
	pool, err := gogitruntime.DescriptorPool()
	if err != nil {
		return err
	}
	commonStorage := filesystem.NewStorageWithOptions(
		osfs.New(commonDirectory, osfs.WithBoundOS()),
		cache.NewObjectLRUDefault(),
		filesystem.Options{Pool: pool},
	)
	manager, err := xworktree.New(commonStorage)
	if err != nil {
		_ = commonStorage.Close()
		return err
	}
	repository, err := manager.Open(osfs.New(root, osfs.WithBoundOS()))
	_ = commonStorage.Close()
	if err != nil {
		return err
	}
	defer repository.Close()
	worktree, err := repository.Worktree()
	if err != nil {
		return err
	}
	openedRoot, err := filepath.EvalSymlinks(worktree.Filesystem().Root())
	if err != nil {
		return err
	}
	if filepath.Clean(openedRoot) != root {
		return fmt.Errorf("opened worktree root does not match discovered root")
	}
	return nil
}
