package main

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/artifactmutation"
	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/spf13/cobra"
)

func newGuardianCommand(a *app) *cobra.Command {
	c := commandGroup("guardian", "Manage credential-provider guardians and tomb recipients")
	c.AddCommand(newGuardianCreate(a), newGuardianShow(a), newGuardianList(a), newGuardianDelete(a), newGuardianChange(a, true), newGuardianChange(a, false))
	return c
}
func selectedProvider(value string) (guardian.Provider, error) {
	if value == "" {
		return guardian.DefaultProvider()
	}
	return guardian.ParseProvider(value)
}
func newGuardianCreate(a *app) *cobra.Command {
	var providerText string
	cmd := &cobra.Command{Use: "create NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		name, err := guardian.ParseName(args[0])
		if err != nil {
			return err
		}
		provider, err := selectedProvider(providerText)
		if err != nil {
			return err
		}
		record, err := a.guardians.Create(name, provider)
		if err != nil {
			return err
		}
		defer record.Destroy()
		data := map[string]any{"name": name, "provider": provider, "fingerprint": record.Fingerprint(), "created_at": record.CreatedAt().Format(time.RFC3339Nano)}
		return a.success(data, func(w io.Writer) error {
			_, e := fmt.Fprintf(w, "Created guardian %s (%s)\n", name, record.Fingerprint())
			return e
		}, nil)
	}}
	cmd.Flags().StringVar(&providerText, "provider", "", "credential provider")
	return cmd
}
func newGuardianShow(a *app) *cobra.Command {
	var providerText string
	cmd := &cobra.Command{Use: "show NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		name, err := guardian.ParseName(args[0])
		if err != nil {
			return err
		}
		provider, err := selectedProvider(providerText)
		if err != nil {
			return err
		}
		record, err := a.guardians.Get(name, provider)
		if err != nil {
			return err
		}
		defer record.Destroy()
		data := map[string]any{"name": name, "provider": provider, "suite": record.Suite(), "fingerprint": record.Fingerprint(), "created_at": record.CreatedAt().Format(time.RFC3339Nano)}
		return a.success(data, func(w io.Writer) error {
			_, e := fmt.Fprintf(w, "%s  %s  %s\n", name, provider, record.Fingerprint())
			return e
		}, nil)
	}}
	cmd.Flags().StringVar(&providerText, "provider", "", "credential provider")
	return cmd
}
func newGuardianList(a *app) *cobra.Command {
	var providerText string
	cmd := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		provider, err := selectedProvider(providerText)
		if err != nil {
			return err
		}
		records, err := a.guardians.List(provider)
		if err != nil {
			return err
		}
		defer func() {
			for _, r := range records {
				r.Destroy()
			}
		}()
		sort.Slice(records, func(i, j int) bool { return records[i].Name() < records[j].Name() })
		items := make([]map[string]any, len(records))
		for i, r := range records {
			items[i] = map[string]any{"name": r.Name(), "provider": provider, "suite": r.Suite(), "fingerprint": r.Fingerprint(), "created_at": r.CreatedAt().Format(time.RFC3339Nano)}
		}
		return a.success(map[string]any{"guardians": items}, func(w io.Writer) error {
			for _, r := range records {
				if _, err := fmt.Fprintf(w, "%s\t%s\n", r.Name(), r.Fingerprint()); err != nil {
					return err
				}
			}
			return nil
		}, nil)
	}}
	cmd.Flags().StringVar(&providerText, "provider", "", "credential provider")
	return cmd
}
func newGuardianDelete(a *app) *cobra.Command {
	var providerText string
	cmd := &cobra.Command{Use: "delete NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		name, err := guardian.ParseName(args[0])
		if err != nil {
			return err
		}
		provider, err := selectedProvider(providerText)
		if err != nil {
			return err
		}
		if err := a.confirm(fmt.Sprintf("Delete guardian %q from %s? Existing artifacts may still reference it. [y/N]: ", name, provider)); err != nil {
			return err
		}
		if err := a.guardians.Delete(name, provider); err != nil {
			return err
		}
		return a.success(map[string]any{"name": name, "provider": provider}, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Deleted guardian %s\n", name); return e }, nil)
	}}
	cmd.Flags().StringVar(&providerText, "provider", "", "credential provider")
	return cmd
}

func newGuardianChange(a *app, add bool) *cobra.Command {
	verb, completed := "remove", "Removed"
	if add {
		verb, completed = "add", "Added"
	}
	var tomb, providerText string
	var all bool
	cmd := &cobra.Command{Use: verb + " --tomb path:WORKTREE NAME (CHAMBER... | --all)", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if all && len(args) > 1 {
			return fmt.Errorf("--all cannot be combined with chambers")
		}
		if !all && len(args) < 2 {
			return fmt.Errorf("one or more chambers or --all is required")
		}
		name, err := guardian.ParseName(args[0])
		if err != nil {
			return err
		}
		provider, err := selectedProvider(providerText)
		if err != nil {
			return err
		}
		record, err := a.guardians.Get(name, provider)
		if err != nil {
			return err
		}
		defer record.Destroy()
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		selected := args[1:]
		scoped, err := session.scopedArtifacts(selected, all)
		if err != nil {
			return err
		}
		builder, err := tombstate.NewMutationBuilder(session.content, session.verified.Manifest.Proclamation.Fingerprint, session.derived.SigningIdentity())
		if err != nil {
			return err
		}
		if add {
			err = artifactmutation.AddGuardian(cmd.Context(), session.tree, artifact.Engine{}, session.derived.AgeIdentity(), record.Recipient(), scoped, builder, builder.Validator(), transaction.Options{})
		} else {
			err = artifactmutation.RemoveGuardian(cmd.Context(), session.tree, artifact.Engine{}, session.derived.AgeIdentity(), record.Recipient(), scoped, builder, builder.Validator(), transaction.Options{})
		}
		if err != nil {
			return err
		}
		return a.success(map[string]any{"guardian": name, "artifacts": len(scoped), "generation": session.verified.Decree.Generation + 1}, func(w io.Writer) error {
			_, e := fmt.Fprintf(w, "%s guardian %s on %d artifact(s)\n", completed, name, len(scoped))
			return e
		}, nil)
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "explicit tomb worktree")
	cmd.Flags().StringVar(&providerText, "provider", "", "credential provider")
	cmd.Flags().BoolVar(&all, "all", false, "select every artifact")
	_ = cmd.MarkFlagRequired("tomb")
	return cmd
}
