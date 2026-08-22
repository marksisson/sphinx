package differential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	gogitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/format/gitattributes"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/memory"
	testgit "github.com/marksisson/sphinx/internal/testgit"
)

type discovery struct {
	Root string
	Bare bool
}

type treeEntry struct {
	Path string
	Mode string
	Type string
	OID  string
}

type blob struct {
	Path string
	Mode string
	OID  string
	Data []byte
}

type pathStatus struct {
	Staging  byte
	Worktree byte
}

type indexEntry struct {
	Path  string
	Mode  string
	OID   string
	Stage int
}

type adapter interface {
	Name() string
	Discover(context.Context, string) (discovery, error)
	Head(context.Context, string) (string, error)
	CommitExists(context.Context, string, string) error
	ListTree(context.Context, string, string) ([]treeEntry, error)
	ReadBlob(context.Context, string, string, string) (blob, error)
	IsAncestor(context.Context, string, string, string) (bool, error)
	Status(context.Context, string) (map[string]pathStatus, error)
	Index(context.Context, string) ([]indexEntry, error)
	Attributes(context.Context, string, string, string, []string) (map[string]string, error)
	HashBlob(context.Context, string, []byte) (string, error)
	ResolveRemote(context.Context, string, string) (string, error)
	CloneMirror(context.Context, string, string) error
}

type nativeAdapter struct{}

func (nativeAdapter) Name() string { return "native-git" }

func (nativeAdapter) Discover(ctx context.Context, start string) (discovery, error) {
	bare, err := nativeGit(ctx, start, "rev-parse", "--is-bare-repository")
	if err != nil {
		return discovery{}, err
	}
	result := discovery{Bare: strings.TrimSpace(string(bare)) == "true"}
	if !result.Bare {
		root, err := nativeGit(ctx, start, "rev-parse", "--path-format=absolute", "--show-toplevel")
		if err != nil {
			return discovery{}, err
		}
		result.Root = filepath.Clean(strings.TrimSpace(string(root)))
	}
	return result, nil
}

func (nativeAdapter) Head(ctx context.Context, repository string) (string, error) {
	output, err := nativeGit(ctx, repository, "rev-parse", "--verify", "HEAD^{commit}")
	return strings.TrimSpace(string(output)), err
}

func (nativeAdapter) CommitExists(ctx context.Context, repository, commit string) error {
	output, err := nativeGit(ctx, repository, "cat-file", "-t", commit)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(output)) != "commit" {
		return fmt.Errorf("object is not a commit")
	}
	return nil
}

func (nativeAdapter) ListTree(ctx context.Context, repository, commit string) ([]treeEntry, error) {
	output, err := nativeGit(ctx, repository, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	var entries []treeEntry
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !found || len(fields) != 3 {
			return nil, fmt.Errorf("malformed native tree result")
		}
		entries = append(entries, treeEntry{Path: string(name), Mode: string(fields[0]), Type: string(fields[1]), OID: string(fields[2])})
	}
	return entries, nil
}

func (nativeAdapter) ReadBlob(ctx context.Context, repository, commit, path string) (blob, error) {
	entries, err := nativeAdapter{}.ListTree(ctx, repository, commit)
	if err != nil {
		return blob{}, err
	}
	var match *treeEntry
	for index := range entries {
		if entries[index].Path == path {
			if match != nil {
				return blob{}, fmt.Errorf("path is ambiguous")
			}
			match = &entries[index]
		}
	}
	if match == nil {
		return blob{}, fmt.Errorf("path not found")
	}
	if match.Type != "blob" {
		return blob{}, fmt.Errorf("path is not a blob")
	}
	data, err := nativeGit(ctx, repository, "cat-file", "blob", match.OID)
	if err != nil {
		return blob{}, err
	}
	return blob{Path: path, Mode: match.Mode, OID: match.OID, Data: data}, nil
}

func (nativeAdapter) IsAncestor(ctx context.Context, repository, ancestor, descendant string) (bool, error) {
	command := exec.CommandContext(ctx, "git", "-C", repository, "merge-base", "--is-ancestor", ancestor, descendant)
	command.Env = testgit.Environment()
	err := command.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func (nativeAdapter) Status(ctx context.Context, repository string) (map[string]pathStatus, error) {
	output, err := nativeGit(ctx, repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	result := make(map[string]pathStatus)
	records := bytes.Split(output, []byte{0})
	for index := 0; index < len(records); index++ {
		record := records[index]
		if len(record) == 0 {
			continue
		}
		if len(record) < 4 || record[2] != ' ' {
			return nil, fmt.Errorf("malformed native status result")
		}
		status := pathStatus{Staging: record[0], Worktree: record[1]}
		name := string(record[3:])
		if status.Staging == 'R' || status.Staging == 'C' {
			index++
			if index >= len(records) || len(records[index]) == 0 {
				return nil, fmt.Errorf("malformed native rename status result")
			}
			name = string(records[index])
		}
		result[name] = status
	}
	return result, nil
}

func (nativeAdapter) Index(ctx context.Context, repository string) ([]indexEntry, error) {
	output, err := nativeGit(ctx, repository, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	var result []indexEntry
	for _, record := range bytes.Split(output, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !found || len(fields) != 3 || len(fields[2]) != 1 {
			return nil, fmt.Errorf("malformed native index result")
		}
		result = append(result, indexEntry{Path: string(name), Mode: string(fields[0]), OID: string(fields[1]), Stage: int(fields[2][0] - '0')})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Stage < result[j].Stage
	})
	return result, nil
}

func (nativeAdapter) Attributes(ctx context.Context, repository, commit, path string, attributes []string) (map[string]string, error) {
	arguments := []string{"check-attr", "-z"}
	if commit != "" {
		arguments = append(arguments, "--source="+commit)
	}
	arguments = append(arguments, attributes...)
	arguments = append(arguments, "--", path)
	output, err := nativeGit(ctx, repository, arguments...)
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(output, []byte{0})
	result := make(map[string]string, len(attributes))
	for index := 0; index+2 < len(parts); index += 3 {
		result[string(parts[index+1])] = string(parts[index+2])
	}
	if len(result) != len(attributes) {
		return nil, fmt.Errorf("native attribute result is incomplete")
	}
	return result, nil
}

func (nativeAdapter) CloneMirror(ctx context.Context, remoteURL, destination string) error {
	_, err := nativeGit(ctx, ".", "clone", "--mirror", "--no-hardlinks", "--", remoteURL, destination)
	return err
}

func (nativeAdapter) ResolveRemote(ctx context.Context, remoteURL, selector string) (string, error) {
	patterns := []string{"HEAD"}
	if selector != "" {
		patterns = []string{"refs/heads/" + selector, "refs/tags/" + selector, "refs/tags/" + selector + "^{}"}
	}
	arguments := append([]string{"ls-remote", "--", remoteURL}, patterns...)
	output, err := nativeGit(ctx, ".", arguments...)
	if err != nil {
		return "", err
	}
	return resolveAdvertisedReferences(output, selector)
}

func (nativeAdapter) HashBlob(ctx context.Context, repository string, data []byte) (string, error) {
	command := exec.CommandContext(ctx, "git", "-C", repository, "hash-object", "--no-filters", "--stdin")
	command.Env = testgit.Environment()
	command.Stdin = bytes.NewReader(data)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("native Git hash-object: %s", strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func nativeGit(ctx context.Context, repository string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", repository}, arguments...)...)
	command.Env = testgit.Environment()
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("native git %s: %s", arguments[0], strings.TrimSpace(string(output)))
	}
	return output, nil
}

type goGitAdapter struct{}

func (goGitAdapter) Name() string { return "go-git" }

func (goGitAdapter) Discover(_ context.Context, start string) (discovery, error) {
	repository, err := git.PlainOpenWithOptions(start, &git.PlainOpenOptions{DetectDotGit: true})
	if errors.Is(err, git.ErrRepositoryNotExists) {
		// DetectDotGit searches for a non-bare worktree. An exact bare path
		// requires the non-detecting open path.
		repository, err = git.PlainOpen(start)
	}
	if err != nil {
		return discovery{}, err
	}
	defer closeRepository(repository)
	worktree, err := repository.Worktree()
	if errors.Is(err, git.ErrIsBareRepository) {
		return discovery{Bare: true}, nil
	}
	if err != nil {
		return discovery{}, err
	}
	root, err := filepath.EvalSymlinks(worktree.Filesystem().Root())
	if err != nil {
		return discovery{}, err
	}
	return discovery{Root: filepath.Clean(root)}, nil
}

func (goGitAdapter) Head(_ context.Context, path string) (string, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return "", err
	}
	defer closeRepository(repository)
	reference, err := repository.Head()
	if err != nil {
		return "", err
	}
	commit, err := repository.CommitObject(reference.Hash())
	if err != nil {
		return "", err
	}
	return commit.Hash.String(), nil
}

func (goGitAdapter) CommitExists(_ context.Context, path, commit string) error {
	repository, err := openGoGit(path)
	if err != nil {
		return err
	}
	defer closeRepository(repository)
	hash, err := parseHash(commit)
	if err != nil {
		return err
	}
	_, err = repository.CommitObject(hash)
	return err
}

func (goGitAdapter) ListTree(_ context.Context, path, commit string) ([]treeEntry, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return nil, err
	}
	defer closeRepository(repository)
	root, err := commitTree(repository, commit)
	if err != nil {
		return nil, err
	}
	entries := make([]treeEntry, 0)
	if err := walkTree(repository, root, "", &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (goGitAdapter) ReadBlob(_ context.Context, path, commit, name string) (blob, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return blob{}, err
	}
	defer closeRepository(repository)
	root, err := commitTree(repository, commit)
	if err != nil {
		return blob{}, err
	}
	entry, err := exactEntry(repository, root, strings.Split(name, "/"))
	if err != nil {
		return blob{}, err
	}
	if entry.Mode == filemode.Dir || entry.Mode == filemode.Submodule {
		return blob{}, fmt.Errorf("path is not a blob")
	}
	objectBlob, err := repository.BlobObject(entry.Hash)
	if err != nil {
		return blob{}, err
	}
	reader, err := objectBlob.Reader()
	if err != nil {
		return blob{}, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return blob{}, err
	}
	return blob{Path: name, Mode: modeString(entry.Mode), OID: entry.Hash.String(), Data: data}, nil
}

func (goGitAdapter) IsAncestor(_ context.Context, path, ancestor, descendant string) (bool, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return false, err
	}
	defer closeRepository(repository)
	ancestorHash, err := parseHash(ancestor)
	if err != nil {
		return false, err
	}
	descendantHash, err := parseHash(descendant)
	if err != nil {
		return false, err
	}
	ancestorCommit, err := repository.CommitObject(ancestorHash)
	if err != nil {
		return false, err
	}
	descendantCommit, err := repository.CommitObject(descendantHash)
	if err != nil {
		return false, err
	}
	return ancestorCommit.IsAncestor(descendantCommit)
}

func (goGitAdapter) Status(_ context.Context, path string) (map[string]pathStatus, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return nil, err
	}
	defer closeRepository(repository)
	worktree, err := repository.Worktree()
	if err != nil {
		return nil, err
	}
	status, err := worktree.StatusWithOptions(git.StatusOptions{Strategy: git.Preload})
	if err != nil {
		return nil, err
	}
	result := make(map[string]pathStatus)
	for name, state := range status {
		if state.Staging == git.Unmodified && state.Worktree == git.Unmodified {
			continue
		}
		result[name] = pathStatus{Staging: byte(state.Staging), Worktree: byte(state.Worktree)}
	}
	return result, nil
}

func (goGitAdapter) Index(_ context.Context, path string) ([]indexEntry, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return nil, err
	}
	defer closeRepository(repository)
	index, err := repository.Storer.Index()
	if err != nil {
		return nil, err
	}
	if index.Version != 2 {
		return nil, fmt.Errorf("unsupported index version %d", index.Version)
	}
	result := make([]indexEntry, 0, len(index.Entries))
	for _, entry := range index.Entries {
		result = append(result, indexEntry{Path: entry.Name, Mode: modeString(entry.Mode), OID: entry.Hash.String(), Stage: int(entry.Stage)})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Path != result[j].Path {
			return result[i].Path < result[j].Path
		}
		return result[i].Stage < result[j].Stage
	})
	return result, nil
}

func (goGitAdapter) Attributes(_ context.Context, path, commit, name string, attributes []string) (map[string]string, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return nil, err
	}
	defer closeRepository(repository)

	var stack []gitattributes.MatchAttribute
	if commit == "" {
		filesystem := osfs.New(path, osfs.WithBoundOS())
		stack, err = gitattributes.ReadPatterns(filesystem, nil)
		if err != nil {
			return nil, err
		}
	} else {
		root, err := commitTree(repository, commit)
		if err != nil {
			return nil, err
		}
		stack, err = committedAttributeStack(repository, root, name)
		if err != nil {
			return nil, err
		}
	}
	information, err := informationAttributes(path)
	if err != nil {
		return nil, err
	}
	stack = append(stack, information...)

	matched := matchAttributePrecedence(stack, strings.Split(name, "/"), attributes)
	result := make(map[string]string, len(attributes))
	for _, attributeName := range attributes {
		attribute, exists := matched[attributeName]
		switch {
		case !exists, attribute.IsUnspecified():
			result[attributeName] = "unspecified"
		case attribute.IsSet():
			result[attributeName] = "set"
		case attribute.IsUnset():
			result[attributeName] = "unset"
		case attribute.IsValueSet():
			result[attributeName] = attribute.Value()
		default:
			return nil, fmt.Errorf("unsupported attribute state for %q", attributeName)
		}
	}
	return result, nil
}

// matchAttributePrecedence works around the pinned matcher's multi-rule
// overwrite behavior by evaluating one rule at a time from highest to lowest
// priority. Native Git uses the first matching state for each attribute.
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

func (goGitAdapter) CloneMirror(ctx context.Context, remoteURL, destination string) error {
	repository, err := git.PlainCloneContext(ctx, destination, &git.CloneOptions{URL: remoteURL, Mirror: true, Bare: true, Tags: git.AllTags})
	if repository != nil {
		closeRepository(repository)
	}
	return err
}

func (goGitAdapter) ResolveRemote(ctx context.Context, remoteURL, selector string) (string, error) {
	remote := git.NewRemote(memory.NewStorage(), &gogitconfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	references, err := remote.ListContext(ctx, &git.ListOptions{PeelingOption: git.AppendPeeled})
	if err != nil {
		return "", err
	}
	byName := make(map[plumbing.ReferenceName]*plumbing.Reference, len(references))
	for _, reference := range references {
		byName[reference.Name()] = reference
	}
	var advertisement bytes.Buffer
	for _, reference := range references {
		hash := reference.Hash()
		if reference.Type() == plumbing.SymbolicReference {
			target, exists := byName[reference.Target()]
			if !exists {
				return "", fmt.Errorf("symbolic remote reference target is missing")
			}
			hash = target.Hash()
		}
		fmt.Fprintf(&advertisement, "%s\t%s\n", hash.String(), reference.Name().String())
	}
	return resolveAdvertisedReferences(advertisement.Bytes(), selector)
}

func (goGitAdapter) HashBlob(_ context.Context, path string, data []byte) (string, error) {
	repository, err := openGoGit(path)
	if err != nil {
		return "", err
	}
	defer closeRepository(repository)
	configuration, err := repository.Config()
	if err != nil {
		return "", err
	}
	hasher := plumbing.NewHasher(configuration.Extensions.ObjectFormat, plumbing.BlobObject, int64(len(data)))
	if _, err := hasher.Write(data); err != nil {
		return "", err
	}
	return hasher.Sum().String(), nil
}

func committedAttributeStack(repository *git.Repository, root *object.Tree, name string) ([]gitattributes.MatchAttribute, error) {
	components := strings.Split(name, "/")
	if len(components) == 0 {
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
		entry, err := exactEntry(repository, current, []string{components[depth]})
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

func informationAttributes(repository string) ([]gitattributes.MatchAttribute, error) {
	gitDirectory := filepath.Join(repository, ".git")
	data, err := os.ReadFile(filepath.Join(gitDirectory, "info", "attributes"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return gitattributes.ReadAttributes(bytes.NewReader(data), nil, true)
}

func openGoGit(path string) (*git.Repository, error) {
	gitDirectory, err := gitDirectoryForPath(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(gitDirectory, "objects", "info", "alternates")); err == nil {
		return nil, fmt.Errorf("object alternates are unsupported")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if entries, err := os.ReadDir(filepath.Join(gitDirectory, "refs", "replace")); err == nil && len(entries) != 0 {
		return nil, fmt.Errorf("replacement refs are unsupported")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	repository, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: false})
	if err != nil {
		return nil, err
	}
	configuration, err := repository.Config()
	if err != nil {
		closeRepository(repository)
		return nil, err
	}
	for _, remote := range configuration.Remotes {
		if remote.Promisor || remote.PartialCloneFilter != "" {
			closeRepository(repository)
			return nil, fmt.Errorf("partial-clone and promisor repositories are unsupported")
		}
	}
	return repository, nil
}

func gitDirectoryForPath(path string) (string, error) {
	dotGit := filepath.Join(path, ".git")
	information, err := os.Lstat(dotGit)
	if errors.Is(err, os.ErrNotExist) {
		if _, configErr := os.Lstat(filepath.Join(path, "config")); configErr == nil {
			return path, nil
		}
		return "", err
	}
	if err != nil {
		return "", err
	}
	if information.IsDir() {
		return dotGit, nil
	}
	if !information.Mode().IsRegular() || information.Size() > 1024 {
		return "", fmt.Errorf("unsupported .git metadata file")
	}
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if !strings.HasPrefix(value, "gitdir: ") {
		return "", fmt.Errorf("malformed .git metadata file")
	}
	gitDirectory := strings.TrimPrefix(value, "gitdir: ")
	if !filepath.IsAbs(gitDirectory) {
		gitDirectory = filepath.Join(path, gitDirectory)
	}
	return filepath.Clean(gitDirectory), nil
}

func closeRepository(repository *git.Repository) {
	if closer, ok := repository.Storer.(io.Closer); ok {
		_ = closer.Close()
	}
}

func commitTree(repository *git.Repository, commit string) (*object.Tree, error) {
	hash, err := parseHash(commit)
	if err != nil {
		return nil, err
	}
	commitObject, err := repository.CommitObject(hash)
	if err != nil {
		return nil, err
	}
	return commitObject.Tree()
}

func walkTree(repository *git.Repository, tree *object.Tree, prefix string, entries *[]treeEntry) error {
	seen := make(map[string]bool, len(tree.Entries))
	for _, entry := range tree.Entries {
		if seen[entry.Name] {
			return fmt.Errorf("duplicate tree entry")
		}
		seen[entry.Name] = true
		name := entry.Name
		if prefix != "" {
			name = prefix + "/" + entry.Name
		}
		if entry.Mode == filemode.Dir {
			subtree, err := repository.TreeObject(entry.Hash)
			if err != nil {
				return err
			}
			if err := walkTree(repository, subtree, name, entries); err != nil {
				return err
			}
			continue
		}
		entryType := "blob"
		if entry.Mode == filemode.Submodule {
			entryType = "commit"
		}
		*entries = append(*entries, treeEntry{Path: name, Mode: modeString(entry.Mode), Type: entryType, OID: entry.Hash.String()})
	}
	return nil
}

func exactEntry(repository *git.Repository, tree *object.Tree, components []string) (object.TreeEntry, error) {
	if len(components) == 0 || components[0] == "" {
		return object.TreeEntry{}, fmt.Errorf("empty path")
	}
	current := tree
	for index, component := range components {
		matches := make([]object.TreeEntry, 0, 1)
		for _, entry := range current.Entries {
			if entry.Name == component {
				matches = append(matches, entry)
			}
		}
		if len(matches) != 1 {
			return object.TreeEntry{}, fmt.Errorf("path is missing or ambiguous")
		}
		entry := matches[0]
		if index == len(components)-1 {
			return entry, nil
		}
		if entry.Mode != filemode.Dir {
			return object.TreeEntry{}, fmt.Errorf("path component is not a tree")
		}
		next, err := repository.TreeObject(entry.Hash)
		if err != nil {
			return object.TreeEntry{}, err
		}
		current = next
	}
	return object.TreeEntry{}, fmt.Errorf("path not found")
}

func resolveAdvertisedReferences(output []byte, selector string) (string, error) {
	var head, tag, peeled string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch {
		case fields[1] == "HEAD" || strings.HasPrefix(fields[1], "refs/heads/"):
			if selector == "" && fields[1] != "HEAD" || selector != "" && fields[1] != "refs/heads/"+selector {
				continue
			}
			head = fields[0]
		case selector != "" && fields[1] == "refs/tags/"+selector+"^{}":
			peeled = fields[0]
		case selector != "" && fields[1] == "refs/tags/"+selector:
			tag = fields[0]
		}
	}
	if selector != "" && head != "" && tag != "" {
		return "", fmt.Errorf("ambiguous branch and tag")
	}
	commit := head
	if commit == "" {
		commit = peeled
	}
	if commit == "" {
		commit = tag
	}
	resolved, err := parseHash(commit)
	if err != nil || resolved.IsZero() {
		return "", fmt.Errorf("selector did not resolve to a full object ID")
	}
	return commit, nil
}

func parseHash(value string) (plumbing.Hash, error) {
	if !plumbing.IsHash(value) {
		return plumbing.ZeroHash, fmt.Errorf("invalid object ID")
	}
	hash, ok := plumbing.FromHex(value)
	if !ok {
		return plumbing.ZeroHash, fmt.Errorf("invalid object ID")
	}
	return hash, nil
}

func modeString(mode filemode.FileMode) string { return fmt.Sprintf("%06o", uint32(mode)) }

func sortTree(entries []treeEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}
