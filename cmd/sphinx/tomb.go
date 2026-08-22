package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/cliresult"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/marksisson/sphinx/internal/lockedresource"
	"github.com/marksisson/sphinx/internal/managedpath"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/marksisson/sphinx/internal/worktree"
	"github.com/spf13/cobra"
)

func newTombCommand(a *app) *cobra.Command {
	c := commandGroup("tomb", "Enroll, update, inspect, validate, and recover tombs")
	c.AddCommand(newTombAdd(a), newTombUpdate(a), newTombStatus(a), newTombList(a), newTombRemove(a), newTombValidate(a), newTombRecover(a))
	return c
}
func projectState(ctx context.Context, a *app, optional bool) (*config.Store, *config.Project, string, error) {
	cwd, err := a.cwd()
	if err != nil {
		return nil, nil, "", err
	}
	store, err := config.Discover(ctx, cwd)
	if err != nil {
		return nil, nil, "", err
	}
	project, err := store.Load(ctx, optional)
	return store, project, cwd, err
}

func newTombAdd(a *app) *cobra.Command {
	var name string
	cmd := &cobra.Command{Use: "add [--name NAME] TARGET", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		store, _, cwd, err := projectState(ctx, a, true)
		if err != nil {
			return err
		}
		global, err := config.LoadGlobal(ctx, a.globalConfig, cwd)
		if err != nil {
			return err
		}
		alias, reference, err := config.ResolveEnrollment(ctx, args[0], name, global, cwd)
		if err != nil {
			return err
		}
		commit, err := gitresource.ResolveCommit(ctx, reference)
		if err != nil {
			return err
		}
		repository, err := a.materializer.Materialize(ctx, reference, commit)
		if err != nil {
			return err
		}
		content, err := repository.ValidateContent(ctx)
		if err != nil {
			return err
		}
		lock, err := tombstate.EnrollmentLock(content, commit, time.Now())
		if err != nil {
			return err
		}
		if err := a.confirm(fmt.Sprintf("Trust proclamation fingerprint %s for tomb %q? [y/N]: ", lock.ProclamationFingerprint, alias)); err != nil {
			return err
		}
		if err := store.Add(ctx, alias, config.ProjectTomb{Reference: reference.String(), Lock: lock}); err != nil {
			return err
		}
		data := map[string]any{"name": alias, "reference": reference.String(), "commit": commit, "proclamation_fingerprint": lock.ProclamationFingerprint, "decree_generation": lock.DecreeGeneration}
		return a.success(data, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Added tomb %s at %s\n", alias, commit); return e }, nil)
	}}
	cmd.Flags().StringVar(&name, "name", "", "project tomb alias")
	return cmd
}

func newTombUpdate(a *app) *cobra.Command {
	return &cobra.Command{Use: "update [NAME]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		store, project, cwd, err := projectState(cmd.Context(), a, false)
		if err != nil {
			return err
		}
		names := args
		updates, err := (lockedresource.Resolver{Materializer: a.materializer}).PrepareTrustedUpdates(cmd.Context(), *project, names, cwd, time.Now)
		if err != nil {
			return err
		}
		if len(updates) == 0 {
			return a.success(map[string]any{"updated": 0}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "All selected tombs are current"); return e }, nil)
		}
		for _, update := range updates {
			if err := a.confirm(fmt.Sprintf("Advance tomb %q from %s to %s? [y/N]: ", update.Name(), update.CurrentCommit(), update.NextCommit())); err != nil {
				return err
			}
		}
		if err := lockedresource.InstallUpdates(cmd.Context(), store, updates); err != nil {
			return err
		}
		return a.success(map[string]any{"updated": len(updates)}, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Updated %d tomb lock(s)\n", len(updates)); return e }, nil)
	}}
}

func newTombStatus(a *app) *cobra.Command {
	return &cobra.Command{Use: "status [NAME]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		_, project, cwd, err := projectState(cmd.Context(), a, false)
		if err != nil {
			return err
		}
		selector := ""
		if len(args) > 0 {
			selector = args[0]
		}
		name, tomb, err := project.Select(cmd.Context(), selector, cwd)
		if err != nil {
			return err
		}
		data := tombData(name, tomb)
		return a.success(data, func(w io.Writer) error {
			_, e := fmt.Fprintf(w, "%s  %s  generation %d\n", name, tomb.Lock.Commit, tomb.Lock.DecreeGeneration)
			return e
		}, nil)
	}}
}
func newTombList(a *app) *cobra.Command {
	return &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, project, _, err := projectState(cmd.Context(), a, false)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(project.Tombs))
		for name := range project.Tombs {
			names = append(names, name)
		}
		sort.Strings(names)
		items := make([]any, 0, len(names))
		for _, name := range names {
			items = append(items, tombData(name, project.Tombs[name]))
		}
		return a.success(map[string]any{"tombs": items}, func(w io.Writer) error {
			for _, name := range names {
				if _, err := fmt.Fprintf(w, "%s\t%s\n", name, project.Tombs[name].Lock.Commit); err != nil {
					return err
				}
			}
			return nil
		}, nil)
	}}
}
func tombData(name string, t config.ProjectTomb) any {
	return struct {
		Name                    string `json:"name"`
		Reference               string `json:"reference"`
		Commit                  string `json:"commit"`
		ProclamationFingerprint string `json:"proclamation_fingerprint"`
		DecreeGeneration        uint64 `json:"decree_generation"`
		LockedAt                string `json:"locked_at"`
	}{name, t.Reference, t.Lock.Commit, t.Lock.ProclamationFingerprint, t.Lock.DecreeGeneration, t.Lock.LockedAt.Format(time.RFC3339Nano)}
}

func newTombRemove(a *app) *cobra.Command {
	return &cobra.Command{Use: "remove NAME", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		store, project, _, err := projectState(cmd.Context(), a, false)
		if err != nil {
			return err
		}
		if _, ok := project.Tombs[args[0]]; !ok {
			return os.ErrNotExist
		}
		if err := a.confirm(fmt.Sprintf("Remove project tomb %q? [y/N]: ", args[0])); err != nil {
			return err
		}
		if err := store.Update(cmd.Context(), func(p *config.Project) error {
			if _, ok := p.Tombs[args[0]]; !ok {
				return os.ErrNotExist
			}
			delete(p.Tombs, args[0])
			return nil
		}); err != nil {
			return err
		}
		return a.success(map[string]any{"name": args[0]}, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Removed tomb %s\n", args[0]); return e }, nil)
	}}
}

func newTombValidate(a *app) *cobra.Command {
	return &cobra.Command{Use: "validate [NAME|path:WORKTREE]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		selector := ""
		if len(args) > 0 {
			selector = args[0]
		}
		if len(selector) >= 5 && selector[:5] == "path:" {
			cwd, _ := a.cwd()
			reference, err := locator.ParseAt(cmd.Context(), selector, cwd)
			if err != nil {
				return err
			}
			content, err := tombstate.LoadWorktreeContent(reference.Path)
			if err != nil {
				return err
			}
			verified, err := tombstate.VerifyCurrent(content)
			if err != nil {
				return err
			}
			derived, err := a.promptProclamation(*verified.Manifest)
			if err != nil {
				return err
			}
			defer derived.Destroy()
			if err := validateAllArtifacts(content, verified.Manifest.Proclamation.AgeRecipient, derived.AgeIdentity()); err != nil {
				return err
			}
			return a.success(map[string]any{"artifacts": len(content.Artifacts), "schemas": len(content.Schemas), "full": true}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Tomb is fully valid"); return e }, nil)
		}
		_, project, cwd, err := projectState(cmd.Context(), a, false)
		if err != nil {
			return err
		}
		name, tomb, err := project.Select(cmd.Context(), selector, cwd)
		if err != nil {
			return err
		}
		reference, err := locator.ParseAt(cmd.Context(), tomb.Reference, cwd)
		if err != nil {
			return err
		}
		repo, err := a.materializer.Materialize(cmd.Context(), reference, tomb.Lock.Commit)
		if err != nil {
			return err
		}
		content, err := repo.ValidateContent(cmd.Context())
		if err != nil {
			return err
		}
		verified, err := tombstate.Verify(content, tomb.Lock.ProclamationFingerprint)
		if err != nil {
			return err
		}
		if verified.Decree.Generation != tomb.Lock.DecreeGeneration {
			return fmt.Errorf("signed decree generation does not match project lock")
		}
		return a.success(map[string]any{"name": name, "artifacts": len(content.Artifacts), "schemas": len(content.Schemas), "full": false}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Tomb public state is valid"); return e }, nil)
	}}
}

func validateAllArtifacts(content *gitresource.Content, recipient string, identity *age.HybridIdentity) error {
	for name, blob := range content.Artifacts {
		inspection, err := (artifact.Engine{}).Inspect(blob.Data, recipient)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", name, err)
		}
		schemaBlob := content.Schemas[inspection.Schema]
		definition, err := schema.Decode(schemaBlob.Data)
		if err != nil {
			return err
		}
		document, _, err := (artifact.Engine{}).DecryptWithIdentities(blob.Data, recipient, []*age.HybridIdentity{identity}, *definition)
		if err != nil {
			return err
		}
		document.Destroy()
	}
	return nil
}

func newTombRecover(a *app) *cobra.Command {
	var rollback bool
	cmd := &cobra.Command{Use: "recover path:WORKTREE --rollback", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if !rollback {
			return cliresult.Usage(fmt.Errorf("--rollback is required"))
		}
		cwd, _ := a.cwd()
		tree, err := worktree.Open(cmd.Context(), args[0], cwd, a.materializer.CacheRoot)
		if err != nil {
			return err
		}
		manifestBytes, err := transaction.RecoveryPreImage(tree, ".tomb/tomb.yaml")
		initialization := os.IsNotExist(err)
		if initialization {
			manifestBytes, err = transaction.RecoveryPostImage(tree, ".tomb/tomb.yaml")
		}
		if err != nil {
			return err
		}
		manifest, err := tombstate.DecodeManifest(manifestBytes)
		if err != nil {
			return err
		}
		authorize := func() error {
			derived, err := a.promptProclamation(*manifest)
			if derived != nil {
				derived.Destroy()
			}
			return err
		}
		validator := func(transaction.View) error {
			if initialization {
				if _, err := os.Lstat(filepath.Join(tree.Root, ".tomb/tomb.yaml")); err == nil {
					content, err := tombstate.LoadWorktreeContent(tree.Root)
					if err != nil {
						return err
					}
					_, err = tombstate.VerifyCurrent(content)
					return err
				} else if !os.IsNotExist(err) {
					return err
				}
				entries, err := managedpath.Discover(tree.Root)
				if err != nil {
					return err
				}
				schemas := 0
				for _, entry := range entries {
					if entry.Kind == managedpath.Artifact {
						return fmt.Errorf("rolled-back initialization retained an artifact")
					}
					schemas++
				}
				if schemas == 0 {
					return fmt.Errorf("rolled-back initialization has no schema")
				}
				for _, path := range []string{".tomb/tomb.yaml", ".tomb/decree.yaml", ".tomb/decree.yaml.sig", ".tomb/rotations/.keep"} {
					if _, err := os.Lstat(filepath.Join(tree.Root, filepath.FromSlash(path))); !os.IsNotExist(err) {
						return fmt.Errorf("rolled-back initialization retained %s", path)
					}
				}
				return nil
			}
			content, err := tombstate.LoadWorktreeContent(tree.Root)
			if err != nil {
				return err
			}
			_, err = tombstate.VerifyCurrent(content)
			return err
		}
		if err := transaction.RecoverRollback(tree, authorize, validator); err != nil {
			return err
		}
		return a.success(map[string]any{"rolled_back": true}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Rolled back tomb transaction"); return e }, nil)
	}}
	cmd.Flags().BoolVar(&rollback, "rollback", false, "restore exact pre-operation paths")
	return cmd
}
