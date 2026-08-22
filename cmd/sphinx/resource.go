package main

import (
	"github.com/marksisson/sphinx/internal/config"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/spf13/cobra"
)

func resolveTombContent(cmd *cobra.Command, a *app, selector string) (*gitresource.Content, *config.ProjectTomb, string, error) {
	cwd, err := a.cwd()
	if err != nil {
		return nil, nil, "", err
	}
	if len(selector) >= 5 && selector[:5] == "path:" {
		reference, err := locator.ParseAt(cmd.Context(), selector, cwd)
		if err != nil {
			return nil, nil, "", err
		}
		commit, err := gitresource.ResolveCommit(cmd.Context(), reference)
		if err != nil {
			return nil, nil, "", err
		}
		repo, err := a.materializer.Materialize(cmd.Context(), reference, commit)
		if err != nil {
			return nil, nil, "", err
		}
		content, err := repo.ValidateContent(cmd.Context())
		return content, nil, reference.String(), err
	}
	_, project, cwd, err := projectState(cmd.Context(), a, false)
	if err != nil {
		return nil, nil, "", err
	}
	name, selected, err := project.Select(cmd.Context(), selector, cwd)
	if err != nil {
		return nil, nil, "", err
	}
	reference, err := locator.ParseAt(cmd.Context(), selected.Reference, cwd)
	if err != nil {
		return nil, nil, "", err
	}
	repo, err := a.materializer.Materialize(cmd.Context(), reference, selected.Lock.Commit)
	if err != nil {
		return nil, nil, "", err
	}
	content, err := repo.ValidateContent(cmd.Context())
	if err != nil {
		return nil, nil, "", err
	}
	return content, &selected, name, nil
}
