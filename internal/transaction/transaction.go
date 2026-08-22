// Package transaction installs exact path-scoped tomb mutations through a
// crash-recoverable journal below the Git administrative directory. It never
// invokes Git and never touches HEAD, refs, the index, or unrelated paths.
package transaction

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marksisson/sphinx/internal/managedpath"
	"github.com/marksisson/sphinx/internal/safefile"
	"github.com/marksisson/sphinx/internal/worktree"
	"golang.org/x/sys/unix"
)

const journalVersion = 1

type PostImage struct {
	Data   []byte
	Mode   fs.FileMode
	Delete bool
}

type View interface {
	Read(path string) ([]byte, fs.FileMode, bool, error)
	ManagedPaths() ([]managedpath.Entry, error)
}
type Validator func(View) error
type Authorizer func() error
type Hook func(phase string, installed int) error

type Options struct {
	Hook         Hook
	Dependencies []string
}

type journal struct {
	Version int            `json:"version"`
	Phase   string         `json:"phase"`
	Entries []journalEntry `json:"entries"`
}

type journalEntry struct {
	Path       string `json:"path"`
	PreExists  bool   `json:"pre_exists"`
	PreData    string `json:"pre_data,omitempty"`
	PreMode    uint32 `json:"pre_mode,omitempty"`
	PreSHA256  string `json:"pre_sha256,omitempty"`
	PostExists bool   `json:"post_exists"`
	PostData   string `json:"post_data,omitempty"`
	PostMode   uint32 `json:"post_mode,omitempty"`
	PostSHA256 string `json:"post_sha256,omitempty"`
}

type virtualView struct {
	root  string
	posts map[string]PostImage
}

func (v virtualView) Read(path string) ([]byte, fs.FileMode, bool, error) {
	if post, ok := v.posts[path]; ok {
		if post.Delete {
			return nil, 0, false, nil
		}
		return append([]byte(nil), post.Data...), post.Mode.Perm(), true, nil
	}
	return readState(v.root, path)
}

func (v virtualView) ManagedPaths() ([]managedpath.Entry, error) {
	entries, err := managedpath.Discover(v.root)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]managedpath.Entry, len(entries)+len(v.posts))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	for path, post := range v.posts {
		entry, managed := managedpath.Classify(path)
		if !managed {
			continue
		}
		if post.Delete {
			delete(byPath, path)
		} else {
			byPath[path] = entry
		}
	}
	result := make([]managedpath.Entry, 0, len(byPath))
	for _, entry := range byPath {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

// RequireCleanJournal fails before worktree guarding when a previous mutation
// requires recovery.
func RequireCleanJournal(tree *worktree.Worktree) error {
	if tree == nil {
		return fmt.Errorf("worktree is required")
	}
	return rejectExisting(filepath.Join(tree.GitDir, "sphinx", "transactions", "current"))
}

// Execute prepares and validates every post-image before installing any path.
// An error after installation begins triggers exact-path rollback.
func Execute(ctx context.Context, tree *worktree.Worktree, guard *worktree.Guard, posts map[string]PostImage, validate Validator, options Options) error {
	if tree == nil || guard == nil || len(posts) == 0 || validate == nil {
		return fmt.Errorf("transaction requires a worktree, guard, post-images, and validator")
	}
	guarded := guard.Targets()
	sort.Strings(guarded)
	expected := make(map[string]bool, len(posts)+len(options.Dependencies))
	for path := range posts {
		expected[path] = true
	}
	for _, path := range options.Dependencies {
		if err := validatePath(path); err != nil {
			return err
		}
		expected[path] = true
	}
	expectedPaths := make([]string, 0, len(expected))
	for path := range expected {
		expectedPaths = append(expectedPaths, path)
	}
	sort.Strings(expectedPaths)
	if strings.Join(guarded, "\x00") != strings.Join(expectedPaths, "\x00") {
		return fmt.Errorf("transaction post-images and dependencies do not exactly match guarded targets")
	}
	unlock, err := lock(tree.GitDir)
	if err != nil {
		return err
	}
	defer unlock()
	journalDir := filepath.Join(tree.GitDir, "sphinx", "transactions", "current")
	if err := rejectExisting(journalDir); err != nil {
		return err
	}
	if err := guard.Revalidate(ctx); err != nil {
		return err
	}
	j, err := prepare(tree.Root, posts)
	if err != nil {
		return err
	}
	if err := validate(virtualView{root: tree.Root, posts: posts}); err != nil {
		return fmt.Errorf("validate complete transaction post-state: %w", err)
	}
	if err := createJournal(journalDir, j); err != nil {
		_ = removeJournal(journalDir)
		return err
	}
	cleanup := false
	defer func() {
		if cleanup {
			_ = removeJournal(journalDir)
		}
	}()
	if err := callHook(options.Hook, "prepared", 0); err != nil {
		cleanup = true
		return err
	}
	installed := 0
	for _, entry := range j.Entries {
		if err := install(tree.Root, entry); err != nil {
			rollbackErr := rollback(tree.Root, j)
			if rollbackErr == nil {
				cleanup = true
			}
			return combine(err, rollbackErr)
		}
		installed++
		if err := callHook(options.Hook, "installed", installed); err != nil {
			rollbackErr := rollback(tree.Root, j)
			if rollbackErr == nil {
				cleanup = true
			}
			return combine(err, rollbackErr)
		}
	}
	if err := validate(filesystemView{root: tree.Root}); err != nil {
		rollbackErr := rollback(tree.Root, j)
		if rollbackErr == nil {
			cleanup = true
		}
		return combine(fmt.Errorf("validate installed transaction state: %w", err), rollbackErr)
	}
	if err := safefile.WriteAtomic(filepath.Join(journalDir, "committed"), []byte("committed\n"), 0o600); err != nil {
		return fmt.Errorf("mark tomb transaction committed: %w", err)
	}
	if err := callHook(options.Hook, "committed", installed); err != nil {
		return err
	}
	cleanup = true
	return nil
}

// RecoveryPreImage returns the exact pre-operation bytes recorded for a target.
// For an unaffected path it reads the current regular file.
func RecoveryPreImage(tree *worktree.Worktree, path string) ([]byte, error) {
	if tree == nil {
		return nil, fmt.Errorf("recovery worktree is required")
	}
	j, err := loadJournal(filepath.Join(tree.GitDir, "sphinx", "transactions", "current"))
	if err != nil {
		return nil, err
	}
	for _, entry := range j.Entries {
		if entry.Path == path {
			if !entry.PreExists {
				return nil, os.ErrNotExist
			}
			data, err := base64.RawStdEncoding.DecodeString(entry.PreData)
			if err != nil {
				return nil, fmt.Errorf("decode recovery pre-image: %w", err)
			}
			return data, nil
		}
	}
	data, _, exists, err := readState(tree.Root, path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	return data, nil
}

// RecoveryPostImage returns the exact intended post-operation bytes for a target.
func RecoveryPostImage(tree *worktree.Worktree, path string) ([]byte, error) {
	if tree == nil {
		return nil, fmt.Errorf("recovery worktree is required")
	}
	j, err := loadJournal(filepath.Join(tree.GitDir, "sphinx", "transactions", "current"))
	if err != nil {
		return nil, err
	}
	for _, entry := range j.Entries {
		if entry.Path == path {
			if !entry.PostExists {
				return nil, os.ErrNotExist
			}
			data, err := base64.RawStdEncoding.DecodeString(entry.PostData)
			if err != nil {
				return nil, fmt.Errorf("decode recovery post-image: %w", err)
			}
			return data, nil
		}
	}
	return nil, os.ErrNotExist
}

type filesystemView struct{ root string }

func (v filesystemView) Read(path string) ([]byte, fs.FileMode, bool, error) {
	return readState(v.root, path)
}
func (v filesystemView) ManagedPaths() ([]managedpath.Entry, error) {
	return managedpath.Discover(v.root)
}

// RecoverRollback validates authorization and restores every pre-image. A
// committed journal is only validated and cleaned up.
func RecoverRollback(tree *worktree.Worktree, authorize Authorizer, validate Validator) error {
	if tree == nil || authorize == nil || validate == nil {
		return fmt.Errorf("recovery requires worktree, proclamation authorization, and validator")
	}
	unlock, err := lock(tree.GitDir)
	if err != nil {
		return err
	}
	defer unlock()
	journalDir := filepath.Join(tree.GitDir, "sphinx", "transactions", "current")
	j, err := loadJournal(journalDir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(journalDir, "committed")); err == nil {
		if err := validate(filesystemView{root: tree.Root}); err != nil {
			return fmt.Errorf("validate committed transaction before cleanup: %w", err)
		}
		return removeJournal(journalDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := authorize(); err != nil {
		return fmt.Errorf("authorize tomb transaction rollback: %w", err)
	}
	if err := rollback(tree.Root, j); err != nil {
		return err
	}
	if err := validate(filesystemView{root: tree.Root}); err != nil {
		return fmt.Errorf("validate rolled-back tomb state: %w", err)
	}
	return removeJournal(journalDir)
}

func prepare(root string, posts map[string]PostImage) (journal, error) {
	paths := make([]string, 0, len(posts))
	for path := range posts {
		if err := validatePath(path); err != nil {
			return journal{}, err
		}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	j := journal{Version: journalVersion, Phase: "prepared", Entries: make([]journalEntry, 0, len(paths))}
	for _, path := range paths {
		pre, mode, exists, err := readState(root, path)
		if err != nil {
			return journal{}, err
		}
		post := posts[path]
		entry := journalEntry{Path: path, PreExists: exists, PostExists: !post.Delete}
		if exists {
			if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				return journal{}, fmt.Errorf("transaction target %q has unsupported special mode bits", path)
			}
			entry.PreData = base64.RawStdEncoding.EncodeToString(pre)
			entry.PreMode = uint32(mode.Perm())
			entry.PreSHA256 = digest(pre)
		}
		clear(pre)
		if !post.Delete {
			postMode := post.Mode.Perm()
			if postMode == 0 || post.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || postMode&0o111 != 0 && (!exists || postMode != mode.Perm()) {
				return journal{}, fmt.Errorf("post-image %q has invalid or newly executable mode", path)
			}
			entry.PostData = base64.RawStdEncoding.EncodeToString(post.Data)
			entry.PostMode = uint32(postMode)
			entry.PostSHA256 = digest(post.Data)
		}
		j.Entries = append(j.Entries, entry)
	}
	return j, nil
}

func createJournal(directory string, j journal) error {
	parent := filepath.Dir(directory)
	if err := safeMkdirAll(parent); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create tomb transaction journal: %w", err)
	}
	var targetList strings.Builder
	for _, entry := range j.Entries {
		targetList.WriteString(entry.Path)
		targetList.WriteByte('\n')
	}
	if err := safefile.WriteAtomic(filepath.Join(directory, "targets"), []byte(targetList.String()), 0o600); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := safefile.WriteAtomic(filepath.Join(directory, "journal.json"), data, 0o600); err != nil {
		return err
	}
	return syncDir(directory)
}

func loadJournal(directory string) (journal, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return journal{}, fmt.Errorf("load tomb transaction journal: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return journal{}, fmt.Errorf("tomb transaction journal directory is unsafe")
	}
	targetBytes, err := os.ReadFile(filepath.Join(directory, "targets"))
	if err != nil {
		return journal{}, fmt.Errorf("read tomb transaction target list: %w", err)
	}
	targets := strings.Split(strings.TrimSuffix(string(targetBytes), "\n"), "\n")
	if len(targets) == 0 || string(targetBytes) != strings.Join(targets, "\n")+"\n" {
		return journal{}, fmt.Errorf("tomb transaction target list is corrupt")
	}
	for index, target := range targets {
		if err := validatePath(target); err != nil || index > 0 && targets[index-1] >= target {
			return journal{}, fmt.Errorf("tomb transaction target list is corrupt")
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "journal.json"))
	if err != nil {
		return journal{}, fmt.Errorf("read tomb transaction journal for affected paths %s: %w", strings.Join(targets, ", "), err)
	}
	var j journal
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&j); err != nil {
		return journal{}, fmt.Errorf("decode tomb transaction journal for affected paths %s: %w", strings.Join(targets, ", "), err)
	}
	canonical, _ := json.Marshal(j)
	canonical = append(canonical, '\n')
	if string(canonical) != string(data) || j.Version != journalVersion || j.Phase != "prepared" || len(j.Entries) == 0 {
		return journal{}, fmt.Errorf("tomb transaction journal is noncanonical or unsupported; affected paths: %s", strings.Join(targets, ", "))
	}
	if len(j.Entries) != len(targets) {
		return journal{}, fmt.Errorf("tomb transaction journal target mismatch; affected paths: %s", strings.Join(targets, ", "))
	}
	seen := map[string]bool{}
	for index := range j.Entries {
		e := &j.Entries[index]
		if err := validatePath(e.Path); err != nil || e.Path != targets[index] || seen[e.Path] || index > 0 && j.Entries[index-1].Path >= e.Path {
			return journal{}, fmt.Errorf("tomb transaction journal target list is invalid")
		}
		seen[e.Path] = true
		if err := validateEntry(*e); err != nil {
			return journal{}, err
		}
	}
	return j, nil
}

func validateEntry(e journalEntry) error {
	for _, state := range []struct {
		exists bool
		data   string
		mode   uint32
		sum    string
	}{{e.PreExists, e.PreData, e.PreMode, e.PreSHA256}, {e.PostExists, e.PostData, e.PostMode, e.PostSHA256}} {
		if !state.exists {
			if state.data != "" || state.mode != 0 || state.sum != "" {
				return fmt.Errorf("journal absence metadata for %q is invalid", e.Path)
			}
			continue
		}
		decoded, err := base64.RawStdEncoding.DecodeString(state.data)
		if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != state.data || digest(decoded) != state.sum || state.mode == 0 {
			clear(decoded)
			return fmt.Errorf("journal image for %q is invalid", e.Path)
		}
		clear(decoded)
	}
	return nil
}

func install(root string, entry journalEntry) error {
	filename := filepath.Join(root, filepath.FromSlash(entry.Path))
	if !entry.PostExists {
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(filepath.Dir(filename))
	}
	data, err := base64.RawStdEncoding.DecodeString(entry.PostData)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := safefile.WriteAtomicWithin(root, filepath.FromSlash(entry.Path), data, fs.FileMode(entry.PostMode)); err != nil {
		return err
	}
	if err := os.Chmod(filename, fs.FileMode(entry.PostMode)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(filename))
}

func rollback(root string, j journal) error {
	for _, entry := range j.Entries {
		if err := currentAllowed(root, entry); err != nil {
			return err
		}
	}
	for _, entry := range j.Entries {
		filename := filepath.Join(root, filepath.FromSlash(entry.Path))
		if !entry.PreExists {
			if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := syncDir(filepath.Dir(filename)); err != nil {
				return err
			}
			continue
		}
		data, err := base64.RawStdEncoding.DecodeString(entry.PreData)
		if err != nil {
			return err
		}
		err = safefile.WriteAtomicWithin(root, filepath.FromSlash(entry.Path), data, fs.FileMode(entry.PreMode))
		clear(data)
		if err != nil {
			return err
		}
		if err := os.Chmod(filename, fs.FileMode(entry.PreMode)); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(filename)); err != nil {
			return err
		}
	}
	return nil
}

func currentAllowed(root string, entry journalEntry) error {
	data, mode, exists, err := readState(root, entry.Path)
	if err != nil {
		return err
	}
	defer clear(data)
	matches := func(wantExists bool, wantMode uint32, wantDigest string) bool {
		if exists != wantExists {
			return false
		}
		if !exists {
			return true
		}
		return uint32(mode.Perm()) == wantMode && digest(data) == wantDigest
	}
	if matches(entry.PreExists, entry.PreMode, entry.PreSHA256) || matches(entry.PostExists, entry.PostMode, entry.PostSHA256) {
		return nil
	}
	return fmt.Errorf("refuse to overwrite unexpected third-party edit at %q during rollback", entry.Path)
}

func readState(root, path string) ([]byte, fs.FileMode, bool, error) {
	if err := validatePath(path); err != nil {
		return nil, 0, false, err
	}
	filename := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Lstat(filename)
	if os.IsNotExist(err) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("transaction target %q must be a regular file", path)
	}
	data, err := os.ReadFile(filename)
	return data, info.Mode(), true, err
}

func rejectExisting(directory string) error {
	if _, err := os.Lstat(directory); err == nil {
		return fmt.Errorf("incomplete tomb transaction requires path-scoped recovery")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}
func validatePath(path string) error {
	printableASCII := true
	for _, value := range []byte(path) {
		if value < 0x21 || value > 0x7e {
			printableASCII = false
			break
		}
	}
	if !printableASCII || path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path || path == "." || strings.HasPrefix(path, "../") {
		return fmt.Errorf("transaction target %q is not a canonical repository-relative path", path)
	}
	return nil
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func callHook(h Hook, phase string, installed int) error {
	if h == nil {
		return nil
	}
	return h(phase, installed)
}
func combine(primary, rollbackErr error) error {
	if rollbackErr == nil {
		return primary
	}
	return fmt.Errorf("%v; rollback failed: %w", primary, rollbackErr)
}

func lock(gitDir string) (func(), error) {
	path := filepath.Join(gitDir, "sphinx-mutation.lock")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open tomb mutation lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN); _ = file.Close() }, nil
}
func safeMkdirAll(path string) error {
	components := []string{}
	for current := path; ; current = filepath.Dir(current) {
		components = append(components, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	for i := len(components) - 1; i >= 0; i-- {
		current := components[i]
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("transaction journal component %q is unsafe", current)
		}
	}
	return nil
}
func syncDir(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
func removeJournal(directory string) error {
	if err := os.RemoveAll(directory); err != nil {
		return err
	}
	return syncDir(filepath.Dir(directory))
}
