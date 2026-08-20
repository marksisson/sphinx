package tomb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	gitReference     = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

type Materialized struct {
	Root     string
	Revision string
	Remote   bool
}

type Source struct {
	location string
	remote   bool
}

func Parse(location string) (Source, error) {
	location = strings.TrimSpace(location)
	if location == "" {
		return Source{}, fmt.Errorf("tomb location is empty")
	}
	if strings.HasPrefix(location, "github:") {
		repository := strings.TrimPrefix(location, "github:")
		if !githubRepository.MatchString(repository) {
			return Source{}, fmt.Errorf("invalid GitHub tomb %q; expected github:OWNER/REPOSITORY", location)
		}
		return Source{location: "https://github.com/" + repository + ".git", remote: true}, nil
	}
	if strings.HasPrefix(location, "git+") {
		repositoryURL := strings.TrimPrefix(location, "git+")
		parsed, err := url.Parse(repositoryURL)
		if err != nil {
			return Source{}, fmt.Errorf("parse Git tomb URL: %w", err)
		}
		if (parsed.Scheme != "https" && parsed.Scheme != "ssh") || parsed.Host == "" {
			return Source{}, fmt.Errorf("Git tomb URL must use git+https or git+ssh")
		}
		if parsed.User != nil && parsed.User.Username() != "git" {
			return Source{}, fmt.Errorf("Git tomb URL must not contain user credentials")
		}
		return Source{location: repositoryURL, remote: true}, nil
	}
	if strings.Contains(location, "://") {
		return Source{}, fmt.Errorf("remote tombs must use github:, git+https:, or git+ssh:")
	}
	return Source{location: location}, nil
}

func (s Source) Materialize(ctx context.Context, cacheDirectory, reference, subdirectory string) (Materialized, error) {
	if err := validateSubdirectory(subdirectory); err != nil {
		return Materialized{}, err
	}
	if !s.remote {
		root, err := secureSubdirectory(s.location, subdirectory)
		if err != nil {
			return Materialized{}, fmt.Errorf("open local Tomb: %w", err)
		}
		return Materialized{Root: root}, nil
	}
	if err := validateReference(reference); err != nil {
		return Materialized{}, err
	}

	cacheDirectory, err := filepath.Abs(cacheDirectory)
	if err != nil {
		return Materialized{}, fmt.Errorf("resolve Tomb cache: %w", err)
	}
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return Materialized{}, fmt.Errorf("create Tomb cache: %w", err)
	}
	if err := os.Chmod(cacheDirectory, 0o700); err != nil {
		return Materialized{}, fmt.Errorf("secure Tomb cache: %w", err)
	}

	digest := sha256.Sum256([]byte(s.location))
	repositoryDirectory := filepath.Join(cacheDirectory, hex.EncodeToString(digest[:16]))
	if _, err := os.Stat(filepath.Join(repositoryDirectory, ".git")); errorsIsNotExist(err) {
		temporaryDirectory, err := os.MkdirTemp(cacheDirectory, ".clone-")
		if err != nil {
			return Materialized{}, fmt.Errorf("create temporary Tomb checkout: %w", err)
		}
		defer os.RemoveAll(temporaryDirectory)
		if err := runGit(ctx, "", "clone", "--no-checkout", "--", s.location, temporaryDirectory); err != nil {
			return Materialized{}, err
		}
		if err := os.Rename(temporaryDirectory, repositoryDirectory); err != nil {
			return Materialized{}, fmt.Errorf("install Tomb checkout: %w", err)
		}
	} else if err != nil {
		return Materialized{}, fmt.Errorf("inspect Tomb checkout: %w", err)
	}

	fetchReference := reference
	if fetchReference == "" {
		fetchReference = "HEAD"
	}
	if err := runGit(ctx, repositoryDirectory, "fetch", "--prune", "--depth=1", "origin", fetchReference); err != nil {
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
		return Materialized{}, fmt.Errorf("resolve Tomb revision: %w", err)
	}
	root, err := secureSubdirectory(repositoryDirectory, subdirectory)
	if err != nil {
		return Materialized{}, fmt.Errorf("open Git Tomb: %w", err)
	}
	return Materialized{
		Root: root, Revision: strings.TrimSpace(string(revisionBytes)), Remote: true,
	}, nil
}

func validateReference(reference string) error {
	if reference == "" {
		return nil
	}
	if !gitReference.MatchString(reference) || strings.HasPrefix(reference, "-") ||
		strings.Contains(reference, "..") || strings.Contains(reference, "@{") {
		return fmt.Errorf("invalid Git reference %q", reference)
	}
	return nil
}

func validateSubdirectory(subdirectory string) error {
	if subdirectory == "" || subdirectory == "." {
		return nil
	}
	if filepath.IsAbs(subdirectory) {
		return fmt.Errorf("Tomb subdirectory must be relative")
	}
	cleaned := filepath.Clean(subdirectory)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("Tomb subdirectory escapes its repository")
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
		return "", fmt.Errorf("Tomb subdirectory escapes its repository")
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
