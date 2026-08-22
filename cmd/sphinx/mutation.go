package main

import (
	"fmt"
	"sort"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/artifactmutation"
	"github.com/marksisson/sphinx/internal/chamber"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/worktree"
	"github.com/spf13/cobra"
)

type mutationSession struct {
	tree     *worktree.Worktree
	content  *gitresource.Content
	verified *tombstate.Verified
	derived  *proclamation.Derived
}

func newMutationSession(cmd *cobra.Command, a *app, raw string) (*mutationSession, error) {
	tree, err := openMutationTree(cmd, a, raw)
	if err != nil {
		return nil, err
	}
	reference, err := locator.ParseAt(cmd.Context(), raw, tree.Root)
	if err != nil {
		return nil, err
	}
	commit, err := gitresource.ResolveCommit(cmd.Context(), reference)
	if err != nil {
		return nil, err
	}
	repo, err := a.materializer.Materialize(cmd.Context(), reference, commit)
	if err != nil {
		return nil, err
	}
	content, err := repo.ValidateContent(cmd.Context())
	if err != nil {
		return nil, err
	}
	verified, err := tombstate.VerifyCurrent(content)
	if err != nil {
		return nil, err
	}
	derived, err := a.promptProclamation(*verified.Manifest)
	if err != nil {
		return nil, err
	}
	return &mutationSession{tree: tree, content: content, verified: verified, derived: derived}, nil
}
func (s *mutationSession) destroy() {
	if s != nil && s.derived != nil {
		s.derived.Destroy()
	}
}
func (s *mutationSession) scopedArtifacts(values []string, all bool) ([]artifactmutation.ScopedArtifact, error) {
	names := values
	if all {
		names = make([]string, 0, len(s.content.Artifacts))
		for name := range s.content.Artifacts {
			names = append(names, name)
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("artifact scope is empty")
	}
	seen := map[string]bool{}
	out := make([]artifactmutation.ScopedArtifact, 0, len(names))
	for _, value := range names {
		parsed, err := chamber.Parse(value)
		if err != nil {
			return nil, err
		}
		name := parsed.String()
		if seen[name] {
			return nil, fmt.Errorf("duplicate chamber %q", name)
		}
		seen[name] = true
		blob, ok := s.content.Artifacts[name]
		if !ok {
			return nil, fmt.Errorf("tomb has no chamber %q", name)
		}
		inspection, err := (artifact.Engine{}).Inspect(blob.Data, s.verified.Manifest.Proclamation.AgeRecipient)
		if err != nil {
			return nil, err
		}
		schemaBlob, ok := s.content.Schemas[inspection.Schema]
		if !ok {
			return nil, fmt.Errorf("artifact schema %q is absent", inspection.Schema)
		}
		definition, err := schema.Decode(schemaBlob.Data)
		if err != nil {
			return nil, err
		}
		mode, err := pathMode(s.tree.Root, blob.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, artifactmutation.ScopedArtifact{Path: blob.Path, Encrypted: blob.Data, Mode: mode, Definition: *definition})
	}
	return out, nil
}
