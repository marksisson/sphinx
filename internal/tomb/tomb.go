package tomb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	locatorpkg "github.com/marksisson/sphinx/internal/locator"
)

type Materialized struct {
	Root     string
	Revision string
	Remote   bool
}

type Locator struct {
	value     string
	location  string
	remote    bool
	base      string
	inlineRef string
	inlineRev string
	inlineDir string
}

// ParseLocator parses a local, GitHub, HTTPS Git, or SSH Git tomb locator.
// Git locators may carry ref, rev, and dir selectors.
func ParseLocator(value string) (Locator, error) {
	parsed, err := locatorpkg.Parse(value)
	if err != nil {
		return Locator{}, err
	}
	if parsed.Type == locatorpkg.TypePath {
		return Locator{value: parsed.String(), location: parsed.Path, base: parsed.Base()}, nil
	}
	return Locator{
		value: parsed.String(), location: parsed.CloneURL(), remote: true, base: parsed.Base(),
		inlineRef: parsed.Ref, inlineRev: parsed.Rev, inlineDir: parsed.Dir,
	}, nil
}

func (l Locator) String() string       { return l.value }
func (l Locator) Remote() bool         { return l.remote }
func (l Locator) Base() string         { return l.base }
func (l Locator) Ref() string          { return l.inlineRef }
func (l Locator) Revision() string     { return l.inlineRev }
func (l Locator) Subdirectory() string { return l.inlineDir }

// Select combines locator-inline selectors with separate configuration fields.
// Conflicting selectors are rejected rather than resolved by precedence.
func (l Locator) Select(ref, subdirectory string) (checkout, tracking, selectedDirectory string, err error) {
	if ref != "" && l.inlineRef != "" && ref != l.inlineRef {
		return "", "", "", fmt.Errorf("configured ref %q conflicts with locator ref %q", ref, l.inlineRef)
	}
	if ref != "" && l.inlineRef == "" && l.inlineRev != "" && ref != l.inlineRev {
		return "", "", "", fmt.Errorf("configured ref %q conflicts with locator revision %q", ref, l.inlineRev)
	}
	tracking = l.inlineRef
	if ref != "" {
		tracking = ref
	}
	checkout = tracking
	if l.inlineRev != "" {
		checkout = l.inlineRev
	}
	if checkout == "" {
		checkout = "HEAD"
	}
	selectedDirectory = l.inlineDir
	if subdirectory != "" && subdirectory != "." {
		if selectedDirectory != "" && selectedDirectory != "." && subdirectory != selectedDirectory {
			return "", "", "", fmt.Errorf("configured path %q conflicts with locator dir %q", subdirectory, selectedDirectory)
		}
		selectedDirectory = subdirectory
	}
	if selectedDirectory == "" {
		selectedDirectory = "."
	}
	return checkout, tracking, selectedDirectory, nil
}

func (l Locator) Materialize(ctx context.Context, cacheDirectory, ref, subdirectory string) (Materialized, error) {
	checkout, _, selectedDirectory, err := l.Select(ref, subdirectory)
	if err != nil {
		return Materialized{}, err
	}
	if err := validateSubdirectory(selectedDirectory); err != nil {
		return Materialized{}, err
	}
	if !l.remote {
		root, err := secureSubdirectory(l.location, selectedDirectory)
		if err != nil {
			return Materialized{}, fmt.Errorf("open local tomb: %w", err)
		}
		return Materialized{Root: root}, nil
	}
	if err := validateGitRef(checkout); err != nil {
		return Materialized{}, err
	}

	cacheDirectory, err = filepath.Abs(cacheDirectory)
	if err != nil {
		return Materialized{}, fmt.Errorf("resolve tomb cache: %w", err)
	}
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return Materialized{}, fmt.Errorf("create tomb cache: %w", err)
	}
	if err := os.Chmod(cacheDirectory, 0o700); err != nil {
		return Materialized{}, fmt.Errorf("secure tomb cache: %w", err)
	}

	// Keep mutable update candidates and immutable served revisions in separate
	// checkouts. Updating a branch must never mutate a running locked tomb.
	digest := sha256.Sum256([]byte(l.location + "\x00" + checkout))
	repositoryDirectory := filepath.Join(cacheDirectory, hex.EncodeToString(digest[:16]))
	if _, err := os.Stat(filepath.Join(repositoryDirectory, ".git")); errorsIsNotExist(err) {
		temporaryDirectory, err := os.MkdirTemp(cacheDirectory, ".clone-")
		if err != nil {
			return Materialized{}, fmt.Errorf("create temporary tomb checkout: %w", err)
		}
		defer os.RemoveAll(temporaryDirectory)
		if err := runGit(ctx, "", "clone", "--no-checkout", "--", l.location, temporaryDirectory); err != nil {
			return Materialized{}, err
		}
		if err := os.Rename(temporaryDirectory, repositoryDirectory); err != nil {
			return Materialized{}, fmt.Errorf("install tomb checkout: %w", err)
		}
	} else if err != nil {
		return Materialized{}, fmt.Errorf("inspect tomb checkout: %w", err)
	}

	if err := runGit(ctx, repositoryDirectory, "fetch", "--prune", "--depth=1", "origin", checkout); err != nil {
		return Materialized{}, err
	}
	if err := runGit(ctx, repositoryDirectory, "checkout", "--force", "--detach", "FETCH_HEAD"); err != nil {
		return Materialized{}, err
	}
	if err := runGit(ctx, repositoryDirectory, "clean", "-ffdx"); err != nil {
		return Materialized{}, err
	}
	revisionBytes, err := exec.CommandContext(ctx, "git", "-C", repositoryDirectory, "rev-parse", "HEAD").Output()
	if err != nil {
		return Materialized{}, fmt.Errorf("resolve tomb revision: %w", err)
	}
	root, err := secureSubdirectory(repositoryDirectory, selectedDirectory)
	if err != nil {
		return Materialized{}, fmt.Errorf("open Git tomb: %w", err)
	}
	return Materialized{
		Root: root, Revision: strings.TrimSpace(string(revisionBytes)), Remote: true,
	}, nil
}

func validateGitRef(ref string) error {
	return locatorpkg.ValidateGitRef(ref)
}

func validateSubdirectory(subdirectory string) error {
	if subdirectory == "" || subdirectory == "." {
		return nil
	}
	if filepath.IsAbs(subdirectory) {
		return fmt.Errorf("tomb subdirectory must be relative")
	}
	cleaned := filepath.Clean(subdirectory)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("tomb subdirectory escapes its repository")
	}
	return nil
}

func secureSubdirectory(root, subdirectory string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return "", err
	}
	candidate := resolvedRoot
	if subdirectory != "" && subdirectory != "." {
		candidate = filepath.Join(resolvedRoot, filepath.Clean(subdirectory))
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("tomb subdirectory escapes its repository")
	}
	return resolvedCandidate, nil
}

func runGit(ctx context.Context, directory string, arguments ...string) error {
	if directory != "" {
		arguments = append([]string{"-C", directory}, arguments...)
	}
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("git %s: %s", arguments[0], message)
	}
	return nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
