// Package mutation couples every artifact/schema post-image to newly
// generated proclamation-signed exhaustive locks before any worktree path is
// changed. Tomb state supplies the concrete decree encoder and signature verifier.
package mutation

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/git/worktree"
	"github.com/marksisson/sphinx/internal/schema"
	managedpath "github.com/marksisson/sphinx/internal/tomb/path"
	"github.com/marksisson/sphinx/internal/tomb/transaction"
)

const (
	DecreePath    = ".tomb/decree.yaml"
	SignaturePath = ".tomb/decree.yaml.sig"
)

type View interface {
	Read(path string) ([]byte, fs.FileMode, bool, error)
	ManagedPaths() ([]managedpath.Entry, error)
}

type SignedState struct {
	Decree    []byte
	Signature []byte
}

type SignedStateBuilder interface {
	// Build must enumerate the complete virtual tomb, regenerate exhaustive
	// artifact/schema locks, and sign the resulting exact decree bytes with the
	// already-authorized proclamation signing identity.
	Build(View) (SignedState, error)
}

type dependencyProvider interface{ Dependencies(View) ([]string, error) }

type Validator func(View) error

type overlay struct {
	root    string
	changes map[string]transaction.PostImage
}

func (v overlay) Read(path string) ([]byte, fs.FileMode, bool, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path || strings.HasPrefix(path, "../") {
		return nil, 0, false, fmt.Errorf("mutation view path %q is invalid", path)
	}
	if change, exists := v.changes[path]; exists {
		if change.Delete {
			return nil, 0, false, nil
		}
		return append([]byte(nil), change.Data...), change.Mode.Perm(), true, nil
	}
	filename := filepath.Join(v.root, filepath.FromSlash(path))
	info, err := os.Lstat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("mutation view path %q is not a regular file", path)
	}
	data, err := os.ReadFile(filename)
	return data, info.Mode(), true, err
}

func (v overlay) ManagedPaths() ([]managedpath.Entry, error) {
	entries, err := managedpath.Discover(v.root)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]managedpath.Entry, len(entries)+len(v.changes))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	for path, change := range v.changes {
		entry, managed := managedpath.Classify(path)
		if !managed {
			continue
		}
		if change.Delete {
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

// Apply refuses an artifact-only write: decree and detached-signature
// post-images can originate only from the required signed-state builder.
func Apply(ctx context.Context, tree *worktree.Worktree, changes map[string]transaction.PostImage, builder SignedStateBuilder, validate Validator, options transaction.Options) error {
	if tree == nil || len(changes) == 0 || builder == nil || validate == nil {
		return fmt.Errorf("artifact mutation requires changes, signed-state builder, and complete-state validator")
	}
	for path := range changes {
		if path == DecreePath || path == SignaturePath {
			return fmt.Errorf("artifact mutation caller cannot supply decree or signature post-images")
		}
		if !isManagedChange(path) {
			return fmt.Errorf("artifact mutation path %q is not an artifact or canonical tomb schema", path)
		}
	}
	if err := transaction.RequireCleanJournal(tree); err != nil {
		return err
	}
	state, err := builder.Build(overlay{root: tree.Root, changes: changes})
	if err != nil {
		return fmt.Errorf("regenerate and sign exhaustive tomb locks: %w", err)
	}
	if len(state.Decree) == 0 || len(state.Signature) == 0 {
		return fmt.Errorf("signed-state builder returned an incomplete decree/signature pair")
	}
	posts := make(map[string]transaction.PostImage, len(changes)+2)
	for path, image := range changes {
		posts[path] = image
	}
	currentView := overlay{root: tree.Root, changes: changes}
	_, decreeMode, decreeExists, err := currentView.Read(DecreePath)
	if err != nil || !decreeExists {
		return fmt.Errorf("read current decree mode")
	}
	_, signatureMode, signatureExists, err := currentView.Read(SignaturePath)
	if err != nil || !signatureExists {
		return fmt.Errorf("read current decree signature mode")
	}
	posts[DecreePath] = transaction.PostImage{Data: append([]byte(nil), state.Decree...), Mode: decreeMode.Perm()}
	posts[SignaturePath] = transaction.PostImage{Data: append([]byte(nil), state.Signature...), Mode: signatureMode.Perm()}
	if provider, ok := builder.(dependencyProvider); ok {
		dependencies, err := provider.Dependencies(overlay{root: tree.Root, changes: changes})
		if err != nil {
			return fmt.Errorf("enumerate signed mutation dependencies: %w", err)
		}
		options.Dependencies = append(options.Dependencies, dependencies...)
	}
	targetSet := make(map[string]bool, len(posts)+len(options.Dependencies))
	for path := range posts {
		targetSet[path] = true
	}
	for _, path := range options.Dependencies {
		targetSet[path] = true
	}
	targets := make([]string, 0, len(targetSet))
	for path := range targetSet {
		targets = append(targets, path)
	}
	guard, err := tree.GuardMutation(ctx, targets)
	if err != nil {
		return err
	}
	return transaction.Execute(ctx, tree, guard, posts, func(view transaction.View) error { return validate(view) }, options)
}

type ScopedArtifact struct {
	Path       string
	Encrypted  []byte
	Mode       fs.FileMode
	Definition schema.Definition
}

// AddGuardian and RemoveGuardian prepare every selected artifact before
// entering one signed transaction. Engine calls consume a distinct fresh data
// key for each artifact; any preparation error leaves the worktree untouched.
func AddGuardian(ctx context.Context, tree *worktree.Worktree, engine artifact.Engine, proclamation *age.HybridIdentity, recipient string, artifacts []ScopedArtifact, builder SignedStateBuilder, validate Validator, options transaction.Options) error {
	return changeGuardian(ctx, tree, engine, proclamation, recipient, artifacts, true, builder, validate, options)
}

func RemoveGuardian(ctx context.Context, tree *worktree.Worktree, engine artifact.Engine, proclamation *age.HybridIdentity, recipient string, artifacts []ScopedArtifact, builder SignedStateBuilder, validate Validator, options transaction.Options) error {
	return changeGuardian(ctx, tree, engine, proclamation, recipient, artifacts, false, builder, validate, options)
}

func changeGuardian(ctx context.Context, tree *worktree.Worktree, engine artifact.Engine, proclamation *age.HybridIdentity, recipient string, artifacts []ScopedArtifact, add bool, builder SignedStateBuilder, validate Validator, options transaction.Options) error {
	if len(artifacts) == 0 {
		return fmt.Errorf("guardian mutation requires at least one selected artifact")
	}
	changes := make(map[string]transaction.PostImage, len(artifacts))
	for _, selected := range artifacts {
		if _, duplicate := changes[selected.Path]; duplicate {
			return fmt.Errorf("guardian mutation duplicates artifact path %q", selected.Path)
		}
		var encrypted []byte
		var err error
		if add {
			encrypted, err = engine.AddRecipient(selected.Encrypted, proclamation, selected.Definition, recipient)
		} else {
			encrypted, err = engine.RemoveRecipient(selected.Encrypted, proclamation, selected.Definition, recipient)
		}
		if err != nil {
			return fmt.Errorf("prepare guardian mutation for %q: %w", selected.Path, err)
		}
		mode := selected.Mode.Perm()
		if mode == 0 {
			mode = 0o600
		}
		changes[selected.Path] = transaction.PostImage{Data: encrypted, Mode: mode}
	}
	return Apply(ctx, tree, changes, builder, validate, options)
}

func isManagedChange(path string) bool { _, managed := managedpath.Classify(path); return managed }
