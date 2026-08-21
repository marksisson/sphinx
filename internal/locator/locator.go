// Package locator parses and normalizes supported sphinx tomb locators.
package locator

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const (
	TypePath   = "path"
	TypeGit    = "git"
	TypeGitHub = "github"
)

var (
	githubComponent = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	hostname        = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]+)?$`)
)

// Locator is a parsed tomb locator. Ref names a mutable branch or tag, Rev
// names an immutable Git commit, and Dir selects a directory within the tomb.
type Locator struct {
	Type  string
	Path  string
	Owner string
	Repo  string
	Ref   string
	Rev   string
	Dir   string
	Host  string
	URL   string
}

// Parse parses the path, github:, and git+https/git+ssh forms accepted by
// sphinx.
func Parse(raw string) (Locator, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Locator{}, fmt.Errorf("tomb locator is empty")
	}
	if strings.HasPrefix(raw, "github:") {
		return parseGitHub(raw)
	}
	if strings.HasPrefix(raw, "git+") {
		return parseGit(raw)
	}
	if strings.HasPrefix(raw, "path:") {
		value, err := url.PathUnescape(strings.TrimPrefix(raw, "path:"))
		if err != nil {
			return Locator{}, fmt.Errorf("parse tomb path: %w", err)
		}
		if value == "" {
			return Locator{}, fmt.Errorf("tomb path is empty")
		}
		return Locator{Type: TypePath, Path: value}, nil
	}
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "http:") || strings.HasPrefix(raw, "https:") {
		return Locator{}, fmt.Errorf("remote tomb locators must use github:, git+https:, or git+ssh:")
	}
	return Locator{Type: TypePath, Path: raw}, nil
}

func parseGitHub(raw string) (Locator, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Locator{}, fmt.Errorf("parse GitHub tomb locator: %w", err)
	}
	if u.Fragment != "" {
		return Locator{}, fmt.Errorf("GitHub tomb locator must not contain a fragment")
	}
	parts, err := splitPathOrOpaque(u, 3)
	if err != nil {
		return Locator{}, fmt.Errorf("parse GitHub tomb path: %w", err)
	}
	if len(parts) < 2 || !githubComponent.MatchString(parts[0]) || !githubComponent.MatchString(parts[1]) {
		return Locator{}, fmt.Errorf("GitHub tomb locator must be github:OWNER/REPOSITORY[/REF]")
	}

	query := u.Query()
	if err := rejectUnknownQuery(query, "ref", "rev", "dir", "host"); err != nil {
		return Locator{}, err
	}
	result := Locator{Type: TypeGitHub, Owner: parts[0], Repo: strings.TrimSuffix(parts[1], ".git")}
	if result.Repo == "" {
		return Locator{}, fmt.Errorf("GitHub tomb repository is empty")
	}
	if len(parts) == 3 {
		if isGitHash(parts[2]) {
			result.Rev = parts[2]
		} else {
			result.Ref = parts[2]
		}
	}
	if value := query.Get("ref"); value != "" {
		if result.Rev != "" {
			return Locator{}, fmt.Errorf("GitHub tomb locator has both a ref and revision")
		}
		if result.Ref != "" && result.Ref != value {
			return Locator{}, fmt.Errorf("GitHub tomb locator has conflicting refs %q and %q", result.Ref, value)
		}
		result.Ref = value
	}
	if value := query.Get("rev"); value != "" {
		if result.Ref != "" {
			return Locator{}, fmt.Errorf("GitHub tomb locator has both a ref and revision")
		}
		if result.Rev != "" && result.Rev != value {
			return Locator{}, fmt.Errorf("GitHub tomb locator has conflicting revisions %q and %q", result.Rev, value)
		}
		if !isGitHash(value) {
			return Locator{}, fmt.Errorf("GitHub tomb revision must be a full Git commit hash")
		}
		result.Rev = value
	}
	result.Dir = query.Get("dir")
	result.Host = query.Get("host")
	if result.Host == "" {
		result.Host = "github.com"
	} else if !hostname.MatchString(result.Host) {
		return Locator{}, fmt.Errorf("invalid GitHub host %q", result.Host)
	}
	if err := validateDir(result.Dir); err != nil {
		return Locator{}, err
	}
	if err := validateRef(result.Ref); err != nil {
		return Locator{}, err
	}
	return result, nil
}

func parseGit(raw string) (Locator, error) {
	u, err := url.Parse(strings.TrimPrefix(raw, "git+"))
	if err != nil {
		return Locator{}, fmt.Errorf("parse Git tomb locator: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "ssh" {
		return Locator{}, fmt.Errorf("Git tomb locator must use git+https or git+ssh")
	}
	if u.Host == "" || u.Fragment != "" {
		return Locator{}, fmt.Errorf("Git tomb locator must have a host and no fragment")
	}
	if u.User != nil {
		if u.Scheme != "ssh" || u.User.Username() != "git" {
			return Locator{}, fmt.Errorf("Git tomb locator must not contain user credentials")
		}
		if _, present := u.User.Password(); present {
			return Locator{}, fmt.Errorf("Git tomb locator must not contain a password")
		}
	}
	query := u.Query()
	if err := rejectUnknownQuery(query, "ref", "rev", "dir"); err != nil {
		return Locator{}, err
	}
	result := Locator{Type: TypeGit, Ref: query.Get("ref"), Rev: query.Get("rev"), Dir: query.Get("dir")}
	if result.Rev != "" && !isGitHash(result.Rev) {
		return Locator{}, fmt.Errorf("Git tomb revision must be a full Git commit hash")
	}
	if err := validateRef(result.Ref); err != nil {
		return Locator{}, err
	}
	if err := validateDir(result.Dir); err != nil {
		return Locator{}, err
	}
	query.Del("ref")
	query.Del("rev")
	query.Del("dir")
	u.RawQuery = query.Encode()
	result.URL = u.String()
	return result, nil
}

// Base returns the canonical tomb locator without a ref, revision, or
// subdirectory. It is suitable for binding a lock file to a repository.
func (r Locator) Base() string {
	switch r.Type {
	case TypePath:
		return "path:" + r.Path
	case TypeGit:
		return "git+" + r.URL
	case TypeGitHub:
		host := ""
		if r.Host != "" && r.Host != "github.com" {
			host = "?host=" + url.QueryEscape(r.Host)
		}
		return "github:" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Repo) + host
	default:
		return ""
	}
}

// CloneURL returns the URL Git should use to clone this tomb.
func (r Locator) CloneURL() string {
	switch r.Type {
	case TypeGit:
		return r.URL
	case TypeGitHub:
		return "https://" + r.Host + "/" + r.Owner + "/" + r.Repo + ".git"
	default:
		return ""
	}
}

// String returns a normalized tomb locator.
func (r Locator) String() string {
	base := r.Base()
	if base == "" || r.Type == TypePath {
		return base
	}
	values := make(url.Values)
	if r.Type == TypeGitHub {
		selector := r.Ref
		if r.Rev != "" {
			selector = r.Rev
		}
		base = "github:" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Repo)
		if selector != "" {
			base += "/" + strings.ReplaceAll(url.PathEscape(selector), "%2F", "/")
		}
		if r.Host != "" && r.Host != "github.com" {
			values.Set("host", r.Host)
		}
	} else {
		if r.Ref != "" {
			values.Set("ref", r.Ref)
		}
		if r.Rev != "" {
			values.Set("rev", r.Rev)
		}
	}
	if r.Dir != "" && r.Dir != "." {
		values.Set("dir", r.Dir)
	}
	if len(values) != 0 {
		base += "?" + values.Encode()
	}
	return base
}

func rejectUnknownQuery(values url.Values, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	for key, entries := range values {
		if !known[key] {
			return fmt.Errorf("unsupported tomb locator query parameter %q", key)
		}
		if len(entries) != 1 {
			return fmt.Errorf("tomb locator query parameter %q must appear once", key)
		}
	}
	return nil
}

// ValidateGitRef applies the safety-relevant Git check-ref-format rules
// to a branch, tag, pull-request ref, or full revision selector.
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

func validateRef(value string) error { return ValidateGitRef(value) }

func validateDir(value string) error {
	if value == "" || value == "." {
		return nil
	}
	if strings.HasPrefix(value, "/") {
		return fmt.Errorf("tomb locator directory must be relative")
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("tomb locator directory escapes the repository")
	}
	return nil
}

func isGitHash(value string) bool {
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

// splitPathOrOpaque preserves slash-containing refs by limiting the split to
// owner, repository, and the remainder.
func splitPathOrOpaque(u *url.URL, count int) ([]string, error) {
	value := u.EscapedPath()
	if value == "" {
		value = u.Opaque
	}
	value = strings.TrimPrefix(strings.TrimSpace(value), "/")
	if value == "" {
		return nil, nil
	}
	parts := strings.SplitN(value, "/", count)
	for index := range parts {
		decoded, err := url.PathUnescape(parts[index])
		if err != nil {
			return nil, err
		}
		parts[index] = decoded
	}
	return parts, nil
}
