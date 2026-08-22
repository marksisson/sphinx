package worktree

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/format/gitattributes"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/go-git/go-git/v6/storage/filesystem/dotgit"
	gogitruntime "github.com/marksisson/sphinx/internal/git/runtime"
)

type openedWorktree struct {
	repository *git.Repository
	worktree   *git.Worktree
}

func (o *openedWorktree) close() { _ = o.repository.Close() }

func (w *Worktree) open(ctx context.Context) (*openedWorktree, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rejectExternalObjectSources(w.CommonDir); err != nil {
		return nil, err
	}
	pool, err := gogitruntime.DescriptorPool()
	if err != nil {
		return nil, err
	}
	var gitFS billy.Filesystem = osfs.New(w.GitDir, osfs.WithBoundOS())
	if w.GitDir != w.CommonDir {
		gitFS = dotgit.NewRepositoryFilesystem(gitFS, osfs.New(w.CommonDir, osfs.WithBoundOS()))
	}
	storage := filesystem.NewStorageWithOptions(gitFS, cache.NewObjectLRUDefault(), filesystem.Options{Pool: pool})
	repository, err := git.Open(storage, osfs.New(w.Root, osfs.WithBoundOS()))
	if err != nil {
		_ = storage.Close()
		return nil, err
	}
	configuration, err := repository.Config()
	if err != nil {
		_ = repository.Close()
		return nil, err
	}
	for _, remote := range configuration.Remotes {
		if remote.Promisor || remote.PartialCloneFilter != "" {
			_ = repository.Close()
			return nil, fmt.Errorf("partial-clone and promisor repositories are unsupported")
		}
	}
	worktree, err := repository.Worktree()
	if err != nil {
		_ = repository.Close()
		return nil, err
	}
	return &openedWorktree{repository: repository, worktree: worktree}, nil
}

func rejectExternalObjectSources(commonDirectory string) error {
	alternates := filepath.Join(commonDirectory, "objects", "info", "alternates")
	if _, err := os.Lstat(alternates); err == nil {
		return fmt.Errorf("object alternates are unsupported")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	replacements := filepath.Join(commonDirectory, "refs", "replace")
	if information, err := os.Lstat(replacements); err == nil {
		if !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("replacement refs metadata is unsafe")
		}
		entries, err := os.ReadDir(replacements)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("replacement refs are unsupported")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	packedPath := filepath.Join(commonDirectory, "packed-refs")
	information, statErr := os.Lstat(packedPath)
	if statErr == nil && (!information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("packed refs metadata is unsafe")
	}
	packed, err := os.ReadFile(packedPath)
	if err == nil {
		for _, line := range bytes.Split(packed, []byte{'\n'}) {
			if fields := bytes.Fields(line); len(fields) == 2 && bytes.HasPrefix(fields[1], []byte("refs/replace/")) {
				return fmt.Errorf("replacement refs are unsupported")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (w *Worktree) rejectUnmergedIndex(ctx context.Context) error {
	indexPath := filepath.Join(w.GitDir, "index")
	if information, err := os.Lstat(indexPath); err == nil {
		if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Git index is not a non-symlink regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	opened, err := w.open(ctx)
	if err != nil {
		return err
	}
	defer opened.close()
	index, err := opened.repository.Storer.Index()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if index.Version != 2 {
		return fmt.Errorf("unsupported Git index version %d", index.Version)
	}
	for _, entry := range index.Entries {
		if entry.Stage != 0 {
			return fmt.Errorf("tomb worktree has unmerged index entries")
		}
	}
	return nil
}

func (w *Worktree) targetStatus(ctx context.Context, target string) (git.FileStatus, bool, error) {
	opened, err := w.open(ctx)
	if err != nil {
		return git.FileStatus{}, false, err
	}
	defer opened.close()
	status, err := opened.worktree.StatusWithOptions(git.StatusOptions{Strategy: git.Preload})
	if err != nil {
		return git.FileStatus{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return git.FileStatus{}, false, err
	}
	state, exists := status[target]
	if !exists || state.Staging == git.Unmodified && state.Worktree == git.Unmodified {
		return git.FileStatus{}, false, nil
	}
	return *state, true, nil
}

func (w *Worktree) validateTargetAttributes(ctx context.Context, target string) error {
	opened, err := w.open(ctx)
	if err != nil {
		return err
	}
	defer opened.close()
	attributeNames := []string{"filter", "working-tree-encoding", "text", "eol"}

	current, err := filesystemAttributeStack(w.Root, target)
	if err != nil {
		return err
	}
	information, err := informationAttributeStack(w.CommonDir)
	if err != nil {
		return err
	}
	current = append(current, information...)
	if err := rejectUnsafeAttributes(target, attributeNames, current); err != nil {
		return err
	}

	head, err := opened.repository.Head()
	if err != nil {
		return err
	}
	commit, err := opened.repository.CommitObject(head.Hash())
	if err != nil {
		return err
	}
	root, err := commit.Tree()
	if err != nil {
		return err
	}
	committed, err := committedAttributeStack(opened.repository, root, target)
	if err != nil {
		return err
	}
	committed = append(committed, information...)
	return rejectUnsafeAttributes(target, attributeNames, committed)
}

func rejectUnsafeAttributes(target string, names []string, stack []gitattributes.MatchAttribute) error {
	matched := matchAttributePrecedence(stack, strings.Split(target, "/"), names)
	for _, name := range names {
		attribute, exists := matched[name]
		value := "unspecified"
		switch {
		case !exists, attribute.IsUnspecified():
		case attribute.IsSet():
			value = "set"
		case attribute.IsUnset():
			value = "unset"
		case attribute.IsValueSet():
			value = attribute.Value()
		default:
			return fmt.Errorf("unsupported attribute state for %q", name)
		}
		safe := value == "unspecified" || name == "text" && value == "unset"
		if !safe {
			return fmt.Errorf("managed worktree path %q has unsafe Git attribute %s=%s", target, name, value)
		}
	}
	return nil
}

func filesystemAttributeStack(root, target string) ([]gitattributes.MatchAttribute, error) {
	components := strings.Split(target, "/")
	var stack []gitattributes.MatchAttribute
	for depth := 0; depth < len(components); depth++ {
		pathComponents := append([]string{root}, components[:depth]...)
		filename := filepath.Join(append(pathComponents, ".gitattributes")...)
		information, err := os.Lstat(filename)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("worktree .gitattributes is not a non-symlink regular file")
		}
		file, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		patterns, readErr := gitattributes.ReadAttributes(file, components[:depth], depth == 0)
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		stack = append(stack, patterns...)
	}
	return stack, nil
}

func informationAttributeStack(commonDirectory string) ([]gitattributes.MatchAttribute, error) {
	filename := filepath.Join(commonDirectory, "info", "attributes")
	information, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("Git information attributes is not a non-symlink regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	patterns, readErr := gitattributes.ReadAttributes(file, nil, true)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return patterns, nil
}

func committedAttributeStack(repository *git.Repository, root *object.Tree, target string) ([]gitattributes.MatchAttribute, error) {
	components := strings.Split(target, "/")
	var stack []gitattributes.MatchAttribute
	current := root
	for depth := 0; depth < len(components); depth++ {
		var attributeEntry *object.TreeEntry
		for index := range current.Entries {
			entry := &current.Entries[index]
			if entry.Name != ".gitattributes" {
				continue
			}
			if attributeEntry != nil {
				return nil, fmt.Errorf("duplicate committed .gitattributes entry")
			}
			attributeEntry = entry
		}
		if attributeEntry != nil {
			if attributeEntry.Mode != filemode.Regular && attributeEntry.Mode != filemode.Executable {
				return nil, fmt.Errorf("committed .gitattributes is not a regular blob")
			}
			blob, err := repository.BlobObject(attributeEntry.Hash)
			if err != nil {
				return nil, err
			}
			reader, err := blob.Reader()
			if err != nil {
				return nil, err
			}
			patterns, readErr := gitattributes.ReadAttributes(reader, components[:depth], depth == 0)
			closeErr := reader.Close()
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			stack = append(stack, patterns...)
		}
		if depth == len(components)-1 {
			break
		}
		entry, err := exactTreeEntry(current, components[depth])
		if err != nil {
			// A target absent from HEAD has no deeper committed attributes.
			break
		}
		if entry.Mode != filemode.Dir {
			break
		}
		current, err = repository.TreeObject(entry.Hash)
		if err != nil {
			return nil, err
		}
	}
	return stack, nil
}

func exactTreeEntry(tree *object.Tree, name string) (object.TreeEntry, error) {
	var result object.TreeEntry
	matches := 0
	for _, entry := range tree.Entries {
		if entry.Name == name {
			result = entry
			matches++
		}
	}
	if matches != 1 {
		return object.TreeEntry{}, fmt.Errorf("tree entry is missing or ambiguous")
	}
	return result, nil
}

// matchAttributePrecedence works around the pinned matcher allowing a lower
// priority rule to overwrite an already-matched higher-priority attribute.
func matchAttributePrecedence(stack []gitattributes.MatchAttribute, path, names []string) map[string]gitattributes.Attribute {
	macros := make([]gitattributes.MatchAttribute, 0)
	for _, rule := range stack {
		if rule.Pattern == nil {
			macros = append(macros, rule)
		}
	}
	result := make(map[string]gitattributes.Attribute, len(names))
	for _, name := range names {
		for index := len(stack) - 1; index >= 0; index-- {
			rule := stack[index]
			if rule.Pattern == nil {
				continue
			}
			matcher := gitattributes.NewMatcher(append(append([]gitattributes.MatchAttribute(nil), macros...), rule))
			values, matched := matcher.Match(path, nil)
			if !matched {
				continue
			}
			if value, exists := values[name]; exists {
				result[name] = value
				break
			}
		}
	}
	return result
}

func (w *Worktree) hashBlob(ctx context.Context, data []byte) (string, error) {
	opened, err := w.open(ctx)
	if err != nil {
		return "", err
	}
	defer opened.close()
	configuration, err := opened.repository.Config()
	if err != nil {
		return "", err
	}
	hasher := plumbing.NewHasher(configuration.Extensions.ObjectFormat, plumbing.BlobObject, int64(len(data)))
	if _, err := hasher.Write(data); err != nil {
		return "", err
	}
	return hasher.Sum().String(), nil
}
