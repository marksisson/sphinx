package lockedresource

import (
	"context"
	"fmt"
	"time"

	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/marksisson/sphinx/internal/tombstate"
)

// PrepareTrustedUpdates combines descendant-only candidate preparation with
// proclamation-transition and signed-generation trust validation. Installation
// remains the existing all-or-nothing project configuration replacement.
func (r Resolver) PrepareTrustedUpdates(ctx context.Context, project config.Project, names []string, cwd string, now func() time.Time) ([]PreparedUpdate, error) {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return r.PrepareUpdates(ctx, project, names, cwd, func(name, candidateCommit string, candidateContent *gitresource.Content) (config.Lock, error) {
		configured, exists := project.Tombs[name]
		if !exists {
			return config.Lock{}, fmt.Errorf("project tomb %q disappeared during trust validation", name)
		}
		reference, err := locator.ParseAt(ctx, configured.Reference, cwd)
		if err != nil {
			return config.Lock{}, err
		}
		currentRepository, err := r.Materializer.Materialize(ctx, reference, configured.Lock.Commit)
		if err != nil {
			return config.Lock{}, err
		}
		currentContent, err := currentRepository.ValidateContent(ctx)
		if err != nil {
			return config.Lock{}, err
		}
		return tombstate.AdvanceLock(configured.Lock, currentContent, candidateContent, candidateCommit, clock())
	})
}
