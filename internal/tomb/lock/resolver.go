// Package lock resolves approved project tombs to exact committed
// artifact and schema blobs in immutable Git object caches.
package lock

import (
	"context"
	"fmt"

	"github.com/marksisson/sphinx/internal/chamber"
	"github.com/marksisson/sphinx/internal/config"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/locator"
)

type Resolver struct {
	Materializer gitresource.Materializer
}

type Artifact struct {
	TombName   string
	Reference  string
	Commit     string
	Chamber    chamber.Path
	Blob       gitresource.Blob
	Content    *gitresource.Content
	repository *gitresource.Repository
}

// Resolve requires a project lock, validates the complete public tomb layout,
// and derives the fixed CHAMBER/artifact.yaml blob at the approved commit.
func (r Resolver) Resolve(ctx context.Context, project config.Project, selector, cwd, chamberText string) (*Artifact, error) {
	chamberPath, err := chamber.Parse(chamberText)
	if err != nil {
		return nil, err
	}
	name, configured, err := project.Select(ctx, selector, cwd)
	if err != nil {
		return nil, err
	}
	reference, err := locator.ParseAt(ctx, configured.Reference, cwd)
	if err != nil {
		return nil, err
	}
	if reference.Rev != "" && reference.Rev != configured.Lock.Commit {
		return nil, fmt.Errorf("immutable tomb selector does not equal its approved lock")
	}
	repository, err := r.Materializer.Materialize(ctx, reference, configured.Lock.Commit)
	if err != nil {
		return nil, err
	}
	content, err := repository.ValidateContent(ctx)
	if err != nil {
		return nil, err
	}
	blob, exists := content.Artifacts[chamberPath.String()]
	if !exists || blob.Path != chamberPath.ArtifactPath() {
		return nil, fmt.Errorf("approved tomb commit has no exact chamber %q", chamberPath.String())
	}
	return &Artifact{TombName: name, Reference: reference.String(), Commit: configured.Lock.Commit,
		Chamber: chamberPath, Blob: blob, Content: content, repository: repository}, nil
}

func (a *Artifact) ReadSchema(reference string) (gitresource.Blob, error) {
	blob, exists := a.Content.Schemas[reference]
	if !exists {
		return gitresource.Blob{}, fmt.Errorf("approved tomb commit has no schema %q", reference)
	}
	return blob, nil
}
