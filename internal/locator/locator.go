// Package locator parses and canonicalizes repository-only tomb references.
package locator

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	gitrepository "github.com/marksisson/sphinx/internal/git/repository"
)

const (
	TypePath   = "path"
	TypeGit    = "git"
	TypeGitHub = "github"
)

var githubComponent = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Locator identifies one Git repository and at most one ref or rev selector.
type Locator struct {
	Type  string
	Path  string
	Owner string
	Repo  string
	Ref   string
	Rev   string
	URL   string
}

func Parse(raw string) (Locator, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return Locator{}, fmt.Errorf("determine current directory: %w", err)
	}
	return ParseAt(context.Background(), raw, cwd)
}

// ParseAt resolves path: references relative to cwd and requires the selected
// path to be exactly a non-bare Git worktree root.
func ParseAt(ctx context.Context, raw, cwd string) (Locator, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return Locator{}, fmt.Errorf("tomb reference is empty or has surrounding whitespace")
	}
	switch {
	case strings.HasPrefix(raw, "github:"):
		return parseGitHub(raw)
	case strings.HasPrefix(raw, "git+"):
		return parseGit(raw)
	case strings.HasPrefix(raw, "path:"):
		return parsePath(ctx, strings.TrimPrefix(raw, "path:"), cwd)
	default:
		return Locator{}, fmt.Errorf("tomb reference must use github:, git+https://, git+ssh://, or path:")
	}
}

func parsePath(ctx context.Context, value, cwd string) (Locator, error) {
	if value == "" || strings.ContainsAny(value, "?#") || strings.Contains(value, "%") {
		return Locator{}, fmt.Errorf("path tomb reference is empty or contains a selector, fragment, or encoding")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(cwd, value)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return Locator{}, fmt.Errorf("resolve tomb worktree: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return Locator{}, fmt.Errorf("resolve tomb worktree without symlinks: %w", err)
	}
	if filepath.Clean(absolute) != filepath.Clean(resolved) {
		return Locator{}, fmt.Errorf("path tomb reference traverses a symlink")
	}
	worktree, err := gitrepository.OpenWorktree(ctx, resolved)
	if err != nil {
		return Locator{}, fmt.Errorf("path tomb is not an exact non-bare Git worktree root: %w", err)
	}
	return Locator{Type: TypePath, Path: worktree.Root}, nil
}

func parseGitHub(raw string) (Locator, error) {
	value := strings.TrimPrefix(raw, "github:")
	if strings.Contains(value, "#") {
		return Locator{}, fmt.Errorf("GitHub tomb reference contains a fragment")
	}
	pathPart, rawQuery, _ := strings.Cut(value, "?")
	if strings.Contains(pathPart, "%") {
		return Locator{}, fmt.Errorf("GitHub tomb repository path contains an encoding")
	}
	parts := strings.Split(pathPart, "/")
	if len(parts) != 2 || !githubComponent.MatchString(parts[0]) || !githubComponent.MatchString(parts[1]) {
		return Locator{}, fmt.Errorf("GitHub tomb reference must be github:OWNER/REPOSITORY")
	}
	repo := strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return Locator{}, fmt.Errorf("GitHub tomb repository is empty")
	}
	ref, rev, err := parseSelector(rawQuery)
	if err != nil {
		return Locator{}, err
	}
	return Locator{Type: TypeGitHub, Owner: parts[0], Repo: repo, Ref: ref, Rev: rev}, nil
}

func parseGit(raw string) (Locator, error) {
	u, err := url.Parse(strings.TrimPrefix(raw, "git+"))
	if err != nil {
		return Locator{}, fmt.Errorf("parse Git tomb reference: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "ssh" {
		return Locator{}, fmt.Errorf("Git tomb reference must use git+https or git+ssh")
	}
	if u.Host == "" || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return Locator{}, fmt.Errorf("Git tomb reference must have a host and repository path and no fragment")
	}
	if u.User != nil {
		if u.Scheme != "ssh" || u.User.Username() != "git" {
			return Locator{}, fmt.Errorf("Git tomb reference contains embedded credentials")
		}
		if _, present := u.User.Password(); present {
			return Locator{}, fmt.Errorf("Git tomb reference contains an embedded password")
		}
	}
	ref, rev, err := parseSelector(u.RawQuery)
	if err != nil {
		return Locator{}, err
	}
	u.RawQuery = ""
	u.ForceQuery = false
	return Locator{Type: TypeGit, URL: u.String(), Ref: ref, Rev: rev}, nil
}

func parseSelector(rawQuery string) (string, string, error) {
	if rawQuery == "" {
		return "", "", nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", fmt.Errorf("parse tomb selector: %w", err)
	}
	for key, entries := range values {
		if key != "ref" && key != "rev" {
			return "", "", fmt.Errorf("unsupported tomb reference query parameter %q", key)
		}
		if len(entries) != 1 || entries[0] == "" {
			return "", "", fmt.Errorf("tomb reference query parameter %q must appear once with a value", key)
		}
	}
	ref, rev := values.Get("ref"), values.Get("rev")
	if ref != "" && rev != "" {
		return "", "", fmt.Errorf("tomb reference cannot contain both ref and rev")
	}
	if err := ValidateGitRef(ref); err != nil {
		return "", "", err
	}
	if rev != "" && !IsFullRevision(rev) {
		return "", "", fmt.Errorf("tomb revision must be a full lowercase Git commit ID")
	}
	return ref, rev, nil
}

func (r Locator) Base() string {
	switch r.Type {
	case TypePath:
		return "path:" + r.Path
	case TypeGit:
		return "git+" + r.URL
	case TypeGitHub:
		return "github:" + r.Owner + "/" + r.Repo
	default:
		return ""
	}
}

func (r Locator) String() string {
	base := r.Base()
	if r.Ref != "" {
		return base + "?ref=" + url.QueryEscape(r.Ref)
	}
	if r.Rev != "" {
		return base + "?rev=" + r.Rev
	}
	return base
}

func (r Locator) CloneURL() string {
	switch r.Type {
	case TypePath:
		return r.Path
	case TypeGit:
		return r.URL
	case TypeGitHub:
		return "https://github.com/" + r.Owner + "/" + r.Repo + ".git"
	default:
		return ""
	}
}

func (r Locator) Immutable() bool { return r.Rev != "" }

func (r Locator) DefaultName() string {
	var value string
	switch r.Type {
	case TypePath:
		value = filepath.Base(r.Path)
	case TypeGit:
		u, _ := url.Parse(r.URL)
		value = filepath.Base(strings.TrimSuffix(u.Path, "/"))
	case TypeGitHub:
		value = r.Repo
	}
	return strings.TrimSuffix(value, ".git")
}

func ValidateGitRef(value string) error {
	if value == "" {
		return nil
	}
	if value == "@" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.HasSuffix(value, ".") || strings.Contains(value, "..") || strings.Contains(value, "@{") || strings.Contains(value, "//") ||
		strings.ContainsAny(value, " ~^:?*[\\") {
		return fmt.Errorf("invalid Git ref %q", value)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("invalid Git ref %q", value)
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return fmt.Errorf("invalid Git ref %q", value)
		}
	}
	return nil
}

func IsFullRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
