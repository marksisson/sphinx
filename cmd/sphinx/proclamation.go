package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/proclamationrotation"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/spf13/cobra"
)

func newProclamationCommand(a *app) *cobra.Command {
	c := commandGroup("proclamation", "Rotate a tomb proclamation")
	c.AddCommand(newProclamationRotate(a))
	return c
}
func newProclamationRotate(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "rotate --tomb path:WORKTREE", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		terminal, err := a.openTerminal()
		if err != nil {
			return err
		}
		credential, err := proclamation.GenerateAndConfirm(terminal, rand.Reader)
		terminal.Close()
		if err != nil {
			return err
		}
		defer credential.Destroy()
		salt, err := proclamation.GenerateSalt(rand.Reader)
		if err != nil {
			return err
		}
		next, err := proclamation.Derive(credential, salt)
		if err != nil {
			return err
		}
		defer next.Destroy()
		if err := proclamationrotation.Rotate(cmd.Context(), session.tree, artifact.Engine{}, session.content, session.derived, next, transaction.Options{}); err != nil {
			return err
		}
		return a.success(map[string]any{"generation": session.verified.Decree.Generation + 1, "proclamation_fingerprint": next.Public().Fingerprint}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Rotated proclamation"); return e }, nil)
	}}
	addPathTomb(cmd, &tomb)
	return cmd
}
