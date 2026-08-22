// Package worktree validates explicit caller-managed Git worktrees for tomb
// mutation without changing Git history, refs, index, remotes, or transport.
package worktree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/marksisson/sphinx/internal/gitenv"
	"github.com/marksisson/sphinx/internal/locator"
	"golang.org/x/sys/unix"
)

type Worktree struct {
	Root      string
	GitDir    string
	CommonDir string
}

type Guard struct {
	worktree *Worktree
	targets  []string
	states   map[string]targetState
}

func (g *Guard) Targets() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.targets...)
}

type targetState struct {
	exists bool
	mode   os.FileMode
	size   int64
	mtime  int64
	digest [32]byte
}

// Open accepts only an explicit path: reference naming the exact non-bare
// worktree root. cacheRoot, when provided, is excluded as a mutation target.
func Open(ctx context.Context, rawReference, cwd, cacheRoot string) (*Worktree, error) {
	reference, err := locator.ParseAt(ctx, rawReference, cwd)
	if err != nil {
		return nil, err
	}
	if reference.Type != locator.TypePath {
		return nil, fmt.Errorf("tomb mutation requires an explicit path: worktree")
	}
	if cacheRoot != "" {
		resolvedCache, err := filepath.EvalSymlinks(cacheRoot)
		if err == nil && within(resolvedCache, reference.Path) {
			return nil, fmt.Errorf("immutable tomb cache cannot be used as a mutation worktree")
		}
	}
	if err := unix.Access(reference.Path, unix.W_OK); err != nil {
		return nil, fmt.Errorf("tomb worktree is not writable: %w", err)
	}
	gitDir, err := gitText(ctx, reference.Path, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return nil, err
	}
	commonDir, err := gitText(ctx, reference.Path, "rev-parse", "--git-common-dir")
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(reference.Path, commonDir)
	}
	gitDir, err = filepath.EvalSymlinks(gitDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Git administrative directory: %w", err)
	}
	commonDir, err = filepath.EvalSymlinks(commonDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Git common directory: %w", err)
	}
	return &Worktree{Root: reference.Path, GitDir: gitDir, CommonDir: commonDir}, nil
}

func (w *Worktree) GuardMutation(ctx context.Context, targets []string) (*Guard, error) {
	return w.guardMutation(ctx, targets, nil)
}

// GuardMutationInputs permits explicitly caller-edited inputs while snapshotting
// them for TOCTOU validation. Every other target must remain Git-clean.
func (w *Worktree) GuardMutationInputs(ctx context.Context, targets, editableInputs []string) (*Guard, error) {
	editable := make(map[string]bool, len(editableInputs))
	for _, path := range editableInputs {
		canonical, err := validateTarget(path)
		if err != nil {
			return nil, err
		}
		editable[canonical] = true
	}
	return w.guardMutation(ctx, targets, editable)
}

func (w *Worktree) guardMutation(ctx context.Context, targets []string, editable map[string]bool) (*Guard, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("mutation target list is empty")
	}
	if err := w.rejectGitOperation(ctx); err != nil {
		return nil, err
	}
	unmerged, err := git(ctx, w.Root, "ls-files", "-u", "-z")
	if err != nil {
		return nil, err
	}
	if len(unmerged) != 0 {
		return nil, fmt.Errorf("tomb worktree has unmerged index entries")
	}
	guard := &Guard{worktree: w, states: make(map[string]targetState, len(targets))}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		canonical, err := validateTarget(target)
		if err != nil {
			return nil, err
		}
		if seen[canonical] {
			return nil, fmt.Errorf("duplicate mutation target %q", canonical)
		}
		seen[canonical] = true
		if err := rejectSymlinksBelow(w.Root, canonical); err != nil {
			return nil, err
		}
		status, err := git(ctx, w.Root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--", ":(literal)"+canonical)
		if err != nil {
			return nil, err
		}
		if len(status) != 0 {
			if !editable[canonical] {
				return nil, fmt.Errorf("mutation target %q has staged, unstaged, or untracked changes", canonical)
			}
			if len(status) < 2 || status[0] != ' ' && !(status[0] == '?' && status[1] == '?') {
				return nil, fmt.Errorf("editable mutation input %q has staged changes", canonical)
			}
		}
		if err := validateAttributes(ctx, w.Root, canonical); err != nil {
			return nil, err
		}
		state, err := inspectTarget(filepath.Join(w.Root, filepath.FromSlash(canonical)))
		if err != nil {
			return nil, err
		}
		guard.targets = append(guard.targets, canonical)
		guard.states[canonical] = state
	}
	return guard, nil
}

// Revalidate detects target changes after guarding and reruns Git state checks.
func (g *Guard) Revalidate(ctx context.Context) error {
	if err := g.worktree.rejectGitOperation(ctx); err != nil {
		return err
	}
	for _, target := range g.targets {
		if err := rejectSymlinksBelow(g.worktree.Root, target); err != nil {
			return err
		}
		state, err := inspectTarget(filepath.Join(g.worktree.Root, filepath.FromSlash(target)))
		if err != nil {
			return err
		}
		if state != g.states[target] {
			return fmt.Errorf("mutation target %q changed after validation", target)
		}
	}
	return nil
}

// ProspectiveBlob validates transformation attributes and returns SHA-256 over
// the exact bytes Git may accept for a managed path.
func (w *Worktree) ProspectiveBlob(ctx context.Context, target string) ([]byte, [32]byte, error) {
	canonical, err := validateTarget(target)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if err := rejectSymlinksBelow(w.Root, canonical); err != nil {
		return nil, [32]byte{}, err
	}
	if err := validateAttributes(ctx, w.Root, canonical); err != nil {
		return nil, [32]byte{}, err
	}
	filename := filepath.Join(w.Root, filepath.FromSlash(canonical))
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, [32]byte{}, fmt.Errorf("managed worktree path %q must be a regular file", canonical)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if bytes.HasPrefix(data, []byte("version https://git-lfs.github.com/spec/v1\n")) {
		return nil, [32]byte{}, fmt.Errorf("managed worktree path %q is a Git LFS pointer", canonical)
	}
	rawOID, err := hashObject(ctx, w.Root, data, "--no-filters")
	if err != nil {
		return nil, [32]byte{}, err
	}
	prospectiveOID, err := hashObject(ctx, w.Root, data, "--path="+canonical)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if rawOID != prospectiveOID {
		return nil, [32]byte{}, fmt.Errorf("managed worktree path %q would be transformed by Git", canonical)
	}
	return data, sha256.Sum256(data), nil
}

func (w *Worktree) rejectGitOperation(ctx context.Context) error {
	for _, directory := range []string{w.GitDir, w.CommonDir} {
		for _, marker := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"} {
			if _, err := os.Lstat(filepath.Join(directory, marker)); err == nil {
				return fmt.Errorf("Git operation %s is in progress", marker)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect Git operation state: %w", err)
			}
		}
	}
	return nil
}

func validateTarget(target string) (string, error) {
	if target == "" || strings.Contains(target, "\\") || filepath.IsAbs(target) {
		return "", fmt.Errorf("mutation target must be a repository-relative slash path")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(target)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != target {
		return "", fmt.Errorf("mutation target %q is not canonical or escapes the worktree", target)
	}
	return clean, nil
}

func rejectSymlinksBelow(root, target string) error {
	current := root
	for _, component := range strings.Split(target, "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("mutation target component %q is a symlink", current)
		}
	}
	return nil
}

func validateAttributes(ctx context.Context, root, target string) error {
	for _, source := range []string{"", "HEAD"} {
		arguments := []string{"check-attr", "-z"}
		if source != "" {
			arguments = append(arguments, "--source="+source)
		}
		arguments = append(arguments, "filter", "working-tree-encoding", "text", "eol", "--", target)
		output, err := git(ctx, root, arguments...)
		if err != nil {
			return err
		}
		parts := bytes.Split(output, []byte{0})
		for index := 0; index+2 < len(parts); index += 3 {
			attribute, value := string(parts[index+1]), string(parts[index+2])
			safe := value == "unspecified" || (attribute == "text" && value == "unset")
			if !safe {
				return fmt.Errorf("managed worktree path %q has unsafe Git attribute %s=%s", target, attribute, value)
			}
		}
	}
	return nil
}

func hashObject(ctx context.Context, root string, data []byte, option string) (string, error) {
	command := exec.CommandContext(ctx, "git", "-C", root, "hash-object", option, "--stdin")
	command.Env = gitenv.Environment()
	command.Stdin = bytes.NewReader(data)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compute prospective Git blob: %s", strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func inspectTarget(filename string) (targetState, error) {
	info, err := os.Lstat(filename)
	if os.IsNotExist(err) {
		return targetState{}, nil
	}
	if err != nil {
		return targetState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return targetState{}, fmt.Errorf("mutation target %q must be a regular file when present", filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return targetState{}, err
	}
	return targetState{exists: true, mode: info.Mode(), size: info.Size(), mtime: info.ModTime().UnixNano(), digest: sha256.Sum256(data)}, nil
}

func within(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func gitText(ctx context.Context, root string, args ...string) (string, error) {
	output, err := git(ctx, root, args...)
	return strings.TrimSpace(string(output)), err
}

func git(ctx context.Context, root string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	command.Env = gitenv.Environment()
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(output)))
	}
	return output, nil
}
