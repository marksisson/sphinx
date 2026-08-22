package resource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	gogitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/format/gitattributes"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/go-git/go-git/v6/storage/filesystem/dotgit"
	"github.com/go-git/go-git/v6/storage/memory"
	gogitruntime "github.com/marksisson/sphinx/internal/git/runtime"
	gittransport "github.com/marksisson/sphinx/internal/git/transport"
)

type openRepository struct {
	repository *git.Repository
}

func (r *openRepository) close() { _ = r.repository.Close() }

func openBareRepository(directory string) (*openRepository, error) {
	return openRepositoryAt(directory, "")
}

func openWorktreeRepository(root string) (*openRepository, error) {
	gitDirectory, commonDirectory, err := worktreeGitDirectories(root)
	if err != nil {
		return nil, err
	}
	return openRepositoryDirectories(gitDirectory, commonDirectory, root)
}

func openRepositoryAt(gitDirectory, worktree string) (*openRepository, error) {
	return openRepositoryDirectories(gitDirectory, gitDirectory, worktree)
}

func openRepositoryDirectories(gitDirectory, commonDirectory, worktree string) (*openRepository, error) {
	if err := rejectUnsafeRepository(gitDirectory, commonDirectory); err != nil {
		return nil, err
	}
	pool, err := gogitruntime.DescriptorPool()
	if err != nil {
		return nil, err
	}
	var gitFS billy.Filesystem = osfs.New(gitDirectory, osfs.WithBoundOS())
	if commonDirectory != gitDirectory {
		commonFS := osfs.New(commonDirectory, osfs.WithBoundOS())
		gitFS = dotgit.NewRepositoryFilesystem(gitFS, commonFS)
	}
	storage := filesystem.NewStorageWithOptions(gitFS, cache.NewObjectLRUDefault(), filesystem.Options{Pool: pool})
	var worktreeFS billy.Filesystem
	if worktree != "" {
		worktreeFS = osfs.New(worktree, osfs.WithBoundOS())
	}
	repository, err := git.Open(storage, worktreeFS)
	if err != nil {
		_ = storage.Close()
		return nil, err
	}
	configuration, err := repository.Config()
	if err != nil {
		_ = storage.Close()
		return nil, err
	}
	for _, remote := range configuration.Remotes {
		if remote.Promisor || remote.PartialCloneFilter != "" {
			_ = storage.Close()
			return nil, fmt.Errorf("partial-clone and promisor repositories are unsupported")
		}
	}
	return &openRepository{repository: repository}, nil
}

func worktreeGitDirectories(root string) (string, string, error) {
	dotGit := filepath.Join(root, ".git")
	information, err := os.Lstat(dotGit)
	if err != nil {
		return "", "", err
	}
	if information.IsDir() {
		return dotGit, dotGit, nil
	}
	if !information.Mode().IsRegular() || information.Size() > 1024 {
		return "", "", fmt.Errorf("unsupported .git metadata file")
	}
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return "", "", err
	}
	value := strings.TrimSpace(string(data))
	if !strings.HasPrefix(value, "gitdir: ") {
		return "", "", fmt.Errorf("malformed .git metadata file")
	}
	gitDirectory := strings.TrimPrefix(value, "gitdir: ")
	if !filepath.IsAbs(gitDirectory) {
		gitDirectory = filepath.Join(root, gitDirectory)
	}
	gitDirectory = filepath.Clean(gitDirectory)
	commonDirectory := gitDirectory
	commonData, err := os.ReadFile(filepath.Join(gitDirectory, "commondir"))
	if err == nil {
		commonValue := strings.TrimSpace(string(commonData))
		if commonValue == "" {
			return "", "", fmt.Errorf("empty linked-worktree common directory")
		}
		commonDirectory = commonValue
		if !filepath.IsAbs(commonDirectory) {
			commonDirectory = filepath.Join(gitDirectory, commonDirectory)
		}
		commonDirectory = filepath.Clean(commonDirectory)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	return gitDirectory, commonDirectory, nil
}

func rejectUnsafeRepository(gitDirectory, commonDirectory string) error {
	for _, directory := range []string{gitDirectory, commonDirectory, filepath.Join(commonDirectory, "objects")} {
		information, err := os.Lstat(directory)
		if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Git administrative component is not a non-symlink directory")
		}
	}
	for _, filename := range []string{filepath.Join(gitDirectory, "HEAD"), filepath.Join(commonDirectory, "config")} {
		information, err := os.Lstat(filename)
		if err != nil || !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Git administrative file is not a non-symlink regular file")
		}
	}
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
	packedInformation, statErr := os.Lstat(packedPath)
	if statErr == nil && (!packedInformation.Mode().IsRegular() || packedInformation.Mode()&os.ModeSymlink != 0) {
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

func parseObjectHash(value string) (plumbing.Hash, error) {
	if !plumbing.IsHash(value) {
		return plumbing.ZeroHash, fmt.Errorf("invalid full Git object ID")
	}
	hash, ok := plumbing.FromHex(value)
	if !ok || hash.IsZero() {
		return plumbing.ZeroHash, fmt.Errorf("invalid full Git object ID")
	}
	return hash, nil
}

func repositoryCommit(repository *git.Repository, value string) (*object.Commit, error) {
	hash, err := parseObjectHash(value)
	if err != nil {
		return nil, err
	}
	return repository.CommitObject(hash)
}

func cloneMirror(ctx context.Context, remoteURL, destination string) error {
	pool, err := gogitruntime.DescriptorPool()
	if err != nil {
		return err
	}
	session, err := gittransport.Open(remoteURL)
	if err != nil {
		return err
	}
	defer session.Close()
	storage := filesystem.NewStorageWithOptions(
		osfs.New(destination, osfs.WithBoundOS()),
		cache.NewObjectLRUDefault(),
		filesystem.Options{Pool: pool},
	)
	repository, err := git.CloneContext(ctx, storage, nil, &git.CloneOptions{
		URL: remoteURL, Mirror: true, Bare: true, Tags: git.AllTags, ClientOptions: session.Options,
	})
	var closeErr error
	if repository != nil {
		closeErr = repository.Close()
	} else {
		closeErr = storage.Close()
	}
	if err != nil {
		if session.Network {
			return gittransport.SafeError("clone", err)
		}
		return err
	}
	return closeErr
}

func resolveRemoteCommit(ctx context.Context, remoteURL, selector string) (string, error) {
	session, err := gittransport.Open(remoteURL)
	if err != nil {
		return "", err
	}
	defer session.Close()
	remote := git.NewRemote(memory.NewStorage(), &gogitconfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	references, err := remote.ListContext(ctx, &git.ListOptions{PeelingOption: git.AppendPeeled, ClientOptions: session.Options})
	if err != nil {
		if session.Network {
			return "", gittransport.SafeError("advertisement", err)
		}
		return "", err
	}
	byName := make(map[plumbing.ReferenceName]*plumbing.Reference, len(references))
	for _, reference := range references {
		byName[reference.Name()] = reference
	}
	var head, tag, peeled plumbing.Hash
	if selector == "" {
		reference, exists := byName[plumbing.HEAD]
		if !exists {
			return "", fmt.Errorf("remote HEAD is missing")
		}
		if reference.Type() == plumbing.SymbolicReference {
			target, exists := byName[reference.Target()]
			if !exists {
				return "", fmt.Errorf("remote HEAD target is missing")
			}
			head = target.Hash()
		} else {
			head = reference.Hash()
		}
	} else {
		if reference, exists := byName[plumbing.NewBranchReferenceName(selector)]; exists {
			head = reference.Hash()
		}
		tagName := plumbing.NewTagReferenceName(selector)
		if reference, exists := byName[tagName]; exists {
			tag = reference.Hash()
		}
		if reference, exists := byName[plumbing.ReferenceName(tagName.String()+"^{}")]; exists {
			peeled = reference.Hash()
		}
		if !head.IsZero() && !tag.IsZero() {
			return "", fmt.Errorf("Git ref %q is ambiguous between a branch and tag", selector)
		}
	}
	resolved := head
	if resolved.IsZero() {
		resolved = peeled
	}
	if resolved.IsZero() {
		resolved = tag
	}
	if resolved.IsZero() {
		return "", fmt.Errorf("Git selector did not resolve to a full commit ID")
	}
	return resolved.String(), nil
}

func listCommitTree(ctx context.Context, repository *git.Repository, commit string) ([]TreeEntry, error) {
	commitObject, err := repositoryCommit(repository, commit)
	if err != nil {
		return nil, err
	}
	root, err := commitObject.Tree()
	if err != nil {
		return nil, err
	}
	entries := make([]TreeEntry, 0)
	if err := walkCommitTree(ctx, repository, root, "", &entries); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func walkCommitTree(ctx context.Context, repository *git.Repository, tree *object.Tree, prefix string, entries *[]TreeEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(tree.Entries))
	for _, entry := range tree.Entries {
		if seen[entry.Name] {
			return fmt.Errorf("duplicate Git tree entry")
		}
		seen[entry.Name] = true
		name := entry.Name
		if prefix != "" {
			name = prefix + "/" + name
		}
		if entry.Mode == filemode.Dir {
			subtree, err := repository.TreeObject(entry.Hash)
			if err != nil {
				return err
			}
			if err := walkCommitTree(ctx, repository, subtree, name, entries); err != nil {
				return err
			}
			continue
		}
		entryType := "blob"
		if entry.Mode == filemode.Submodule {
			entryType = "commit"
		}
		*entries = append(*entries, TreeEntry{Path: name, Mode: formatMode(entry.Mode), Type: entryType, OID: entry.Hash.String()})
	}
	return nil
}

func exactTreeEntry(repository *git.Repository, tree *object.Tree, name string) (object.TreeEntry, error) {
	components := strings.Split(name, "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return object.TreeEntry{}, fmt.Errorf("empty or non-canonical Git path")
	}
	current := tree
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return object.TreeEntry{}, fmt.Errorf("empty or non-canonical Git path")
		}
		matches := make([]object.TreeEntry, 0, 1)
		for _, entry := range current.Entries {
			if entry.Name == component {
				matches = append(matches, entry)
			}
		}
		if len(matches) != 1 {
			return object.TreeEntry{}, fmt.Errorf("Git path is missing or ambiguous")
		}
		entry := matches[0]
		if index == len(components)-1 {
			return entry, nil
		}
		if entry.Mode != filemode.Dir {
			return object.TreeEntry{}, fmt.Errorf("Git path component is not a tree")
		}
		next, err := repository.TreeObject(entry.Hash)
		if err != nil {
			return object.TreeEntry{}, err
		}
		current = next
	}
	return object.TreeEntry{}, fmt.Errorf("Git path is missing")
}

func committedAttributes(repository *git.Repository, commit, name string, names []string) (map[string]string, error) {
	commitObject, err := repositoryCommit(repository, commit)
	if err != nil {
		return nil, err
	}
	root, err := commitObject.Tree()
	if err != nil {
		return nil, err
	}
	stack, err := committedAttributeStack(repository, root, name)
	if err != nil {
		return nil, err
	}
	matched := matchAttributePrecedence(stack, strings.Split(name, "/"), names)
	result := make(map[string]string, len(names))
	for _, name := range names {
		attribute, exists := matched[name]
		switch {
		case !exists, attribute.IsUnspecified():
			result[name] = "unspecified"
		case attribute.IsSet():
			result[name] = "set"
		case attribute.IsUnset():
			result[name] = "unset"
		case attribute.IsValueSet():
			result[name] = attribute.Value()
		default:
			return nil, fmt.Errorf("unsupported attribute state for %q", name)
		}
	}
	return result, nil
}

func committedAttributeStack(repository *git.Repository, root *object.Tree, name string) ([]gitattributes.MatchAttribute, error) {
	components := strings.Split(name, "/")
	if name == "" || len(components) == 0 {
		return nil, fmt.Errorf("empty attribute path")
	}
	var stack []gitattributes.MatchAttribute
	current := root
	for depth := 0; depth < len(components); depth++ {
		for _, entry := range current.Entries {
			if entry.Name != ".gitattributes" {
				continue
			}
			if entry.Mode != filemode.Regular && entry.Mode != filemode.Executable {
				return nil, fmt.Errorf(".gitattributes is not a regular blob")
			}
			blob, err := repository.BlobObject(entry.Hash)
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
			break
		}
		if depth == len(components)-1 {
			break
		}
		entry, err := exactTreeEntry(repository, current, components[depth])
		if err != nil {
			return nil, err
		}
		if entry.Mode != filemode.Dir {
			return nil, fmt.Errorf("attribute path parent is not a tree")
		}
		current, err = repository.TreeObject(entry.Hash)
		if err != nil {
			return nil, err
		}
	}
	return stack, nil
}

// matchAttributePrecedence works around the pinned matcher's lower-priority
// overwrite behavior by evaluating rules one at a time, highest priority first.
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
			matcherStack := append(append([]gitattributes.MatchAttribute(nil), macros...), rule)
			values, matched := gitattributes.NewMatcher(matcherStack).Match(path, nil)
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

func formatMode(mode filemode.FileMode) string { return fmt.Sprintf("%06o", uint32(mode)) }
