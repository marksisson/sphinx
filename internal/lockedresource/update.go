package lockedresource

import (
	"context"
	"fmt"
	"sort"

	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/locator"
)

type PreparedUpdate struct {
	name    string
	current string
	next    string
	lock    config.Lock
}

func (u PreparedUpdate) Name() string          { return u.name }
func (u PreparedUpdate) CurrentCommit() string { return u.current }
func (u PreparedUpdate) NextCommit() string    { return u.next }

// PrepareUpdates resolves and validates all selected mutable references before
// any project configuration is changed. Trust derives the fingerprint,
// generation, and timestamp after later-phase signed-state validation.
func (r Resolver) PrepareUpdates(
	ctx context.Context,
	project config.Project,
	names []string,
	cwd string,
	trust func(string, string, *gitresource.Content) (config.Lock, error),
) ([]PreparedUpdate, error) {
	selected := names
	if len(selected) == 0 {
		selected = make([]string, 0, len(project.Tombs))
		for name := range project.Tombs {
			selected = append(selected, name)
		}
		sort.Strings(selected)
	}
	seen := make(map[string]bool, len(selected))
	updates := make([]PreparedUpdate, 0, len(selected))
	for _, name := range selected {
		if seen[name] {
			return nil, fmt.Errorf("duplicate tomb update target %q", name)
		}
		seen[name] = true
		tomb, exists := project.Tombs[name]
		if !exists {
			return nil, fmt.Errorf("project tomb %q does not exist", name)
		}
		reference, err := locator.ParseAt(ctx, tomb.Reference, cwd)
		if err != nil {
			return nil, err
		}
		if reference.Immutable() {
			if reference.Rev != tomb.Lock.Commit {
				return nil, fmt.Errorf("immutable tomb %q selector differs from its lock", name)
			}
			continue
		}
		candidateCommit, err := gitresource.ResolveCommit(ctx, reference)
		if err != nil {
			return nil, fmt.Errorf("resolve tomb %q candidate: %w", name, err)
		}
		if candidateCommit == tomb.Lock.Commit {
			continue
		}
		repository, err := r.Materializer.Materialize(ctx, reference, candidateCommit)
		if err != nil {
			return nil, fmt.Errorf("materialize tomb %q candidate: %w", name, err)
		}
		descendant, err := repository.IsDescendant(ctx, tomb.Lock.Commit, candidateCommit)
		if err != nil {
			return nil, fmt.Errorf("verify tomb %q ancestry: %w", name, err)
		}
		if !descendant {
			return nil, fmt.Errorf("tomb %q candidate commit does not descend from its lock", name)
		}
		content, err := repository.ValidateContent(ctx)
		if err != nil {
			return nil, fmt.Errorf("validate tomb %q candidate content: %w", name, err)
		}
		if trust == nil {
			return nil, fmt.Errorf("tomb %q candidate requires signed-state trust validation", name)
		}
		nextLock, err := trust(name, candidateCommit, content)
		if err != nil {
			return nil, fmt.Errorf("validate tomb %q candidate trust: %w", name, err)
		}
		if nextLock.Commit != candidateCommit {
			return nil, fmt.Errorf("tomb %q trust validator returned a different commit", name)
		}
		if err := nextLock.Validate(); err != nil {
			return nil, err
		}
		updates = append(updates, PreparedUpdate{name: name, current: tomb.Lock.Commit, next: candidateCommit, lock: nextLock})
	}
	return updates, nil
}

// InstallUpdates performs one stale-checked atomic project-config replacement.
func InstallUpdates(ctx context.Context, store *config.Store, updates []PreparedUpdate) error {
	proposals := make([]config.LockProposal, len(updates))
	for index, update := range updates {
		proposals[index] = config.LockProposal{Name: update.name, ExpectedCommit: update.current, Lock: update.lock}
	}
	return store.UpdateLocks(ctx, proposals)
}
