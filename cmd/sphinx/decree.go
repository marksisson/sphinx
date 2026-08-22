package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/marksisson/sphinx/internal/cliresult"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/marksisson/sphinx/internal/managedpath"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/marksisson/sphinx/internal/worktree"
	"github.com/spf13/cobra"
)

func newDecreeCommand(a *app) *cobra.Command {
	c := commandGroup("decree", "Initialize, sign, validate, and show reveal policy")
	c.AddCommand(newDecreeInit(a), newDecreeSign(a), newDecreeValidate(a), newDecreeShow(a))
	return c
}
func openMutationTree(cmd *cobra.Command, a *app, raw string) (*worktree.Worktree, error) {
	cwd, err := a.cwd()
	if err != nil {
		return nil, err
	}
	return worktree.Open(cmd.Context(), raw, cwd, a.materializer.CacheRoot)
}
func schemaBlobs(root string) (map[string]gitresource.Blob, []string, error) {
	entries, err := managedpath.Discover(root)
	if err != nil {
		return nil, nil, err
	}
	blobs := map[string]gitresource.Blob{}
	paths := []string{}
	for _, entry := range entries {
		if entry.Kind == managedpath.Artifact {
			return nil, nil, fmt.Errorf("decree initialization requires a tomb with no artifacts")
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			return nil, nil, err
		}
		blobs[entry.Key] = gitresource.Blob{Path: entry.Path, Data: data}
		paths = append(paths, entry.Path)
	}
	if len(blobs) == 0 {
		return nil, nil, fmt.Errorf("decree initialization requires at least one schema")
	}
	return blobs, paths, nil
}

func newDecreeInit(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "init --tomb path:WORKTREE", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tree, err := openMutationTree(cmd, a, tomb)
		if err != nil {
			return err
		}
		schemas, paths, err := schemaBlobs(tree.Root)
		if err != nil {
			return err
		}
		for _, path := range []string{".tomb/tomb.yaml", ".tomb/decree.yaml", ".tomb/decree.yaml.sig", ".tomb/rotations/.keep"} {
			if _, err := os.Lstat(filepath.Join(tree.Root, filepath.FromSlash(path))); err == nil {
				return fmt.Errorf("tomb metadata already exists")
			} else if !os.IsNotExist(err) {
				return err
			}
		}
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
		derived, err := proclamation.Derive(credential, salt)
		if err != nil {
			return err
		}
		defer derived.Destroy()
		state, err := tombstate.Initialize(schemas, derived, rand.Reader)
		if err != nil {
			return err
		}
		posts := map[string]transaction.PostImage{".tomb/tomb.yaml": {Data: state.Manifest, Mode: 0o600}, ".tomb/decree.yaml": {Data: state.Decree, Mode: 0o600}, ".tomb/decree.yaml.sig": {Data: state.Signature, Mode: 0o600}, ".tomb/rotations/.keep": {Data: []byte{}, Mode: 0o600}}
		targets := append([]string{".tomb/tomb.yaml", ".tomb/decree.yaml", ".tomb/decree.yaml.sig", ".tomb/rotations/.keep"}, paths...)
		guard, err := tree.GuardMutationInputs(cmd.Context(), targets, paths)
		if err != nil {
			return err
		}
		validator := tombstate.MutationValidator(derived.Public().Fingerprint, nil)
		if err := transaction.Execute(cmd.Context(), tree, guard, posts, func(view transaction.View) error { return validator(view) }, transaction.Options{Dependencies: paths}); err != nil {
			return err
		}
		return a.success(map[string]any{"tomb_id": state.TombID, "generation": uint64(1), "proclamation_fingerprint": derived.Public().Fingerprint}, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Initialized tomb %s\n", state.TombID); return e }, nil)
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "explicit tomb worktree")
	_ = cmd.MarkFlagRequired("tomb")
	return cmd
}

func newDecreeSign(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "sign --tomb path:WORKTREE", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		tree, err := openMutationTree(cmd, a, tomb)
		if err != nil {
			return err
		}
		reference, err := locator.ParseAt(cmd.Context(), tomb, tree.Root)
		if err != nil {
			return err
		}
		commit, err := gitresource.ResolveCommit(cmd.Context(), reference)
		if err != nil {
			return err
		}
		repo, err := a.materializer.Materialize(cmd.Context(), reference, commit)
		if err != nil {
			return err
		}
		committed, err := repo.ValidateContent(cmd.Context())
		if err != nil {
			return err
		}
		verified, err := tombstate.VerifyCurrent(committed)
		if err != nil {
			return err
		}
		derived, err := a.promptProclamation(*verified.Manifest)
		if err != nil {
			return err
		}
		defer derived.Destroy()
		candidate, err := tombstate.LoadWorktreeContent(tree.Root)
		if err != nil {
			return err
		}
		if !bytes.Equal(candidate.Manifest.Data, committed.Manifest.Data) {
			return fmt.Errorf("tomb manifest cannot be edited by decree sign")
		}
		if len(candidate.Rotations) != len(committed.Rotations) {
			return fmt.Errorf("proclamation rotations cannot be edited by decree sign")
		}
		for sequence, current := range committed.Rotations {
			next, ok := candidate.Rotations[sequence]
			if !ok || !bytes.Equal(current.Transition.Data, next.Transition.Data) || !bytes.Equal(current.From.Data, next.From.Data) || !bytes.Equal(current.To.Data, next.To.Data) {
				return fmt.Errorf("proclamation rotation %08d cannot be edited by decree sign", sequence)
			}
		}
		decreeBytes, signature, err := tombstate.SignDraft(candidate.Manifest.Data, candidate.Decree.Data, verified.Decree.Generation, candidate.Artifacts, candidate.Schemas, derived.SigningIdentity())
		if err != nil {
			return err
		}
		decreeMode, err := pathMode(tree.Root, ".tomb/decree.yaml")
		if err != nil {
			return err
		}
		signatureMode, err := pathMode(tree.Root, ".tomb/decree.yaml.sig")
		if err != nil {
			return err
		}
		posts := map[string]transaction.PostImage{".tomb/decree.yaml": {Data: decreeBytes, Mode: decreeMode}, ".tomb/decree.yaml.sig": {Data: signature, Mode: signatureMode}}
		targets := []string{".tomb/decree.yaml", ".tomb/decree.yaml.sig", ".tomb/tomb.yaml"}
		editable := []string{".tomb/decree.yaml"}
		dependencies := []string{".tomb/tomb.yaml"}
		entries, _ := managedpath.Discover(tree.Root)
		for _, entry := range entries {
			targets = append(targets, entry.Path)
			dependencies = append(dependencies, entry.Path)
			if entry.Kind == managedpath.Schema {
				editable = append(editable, entry.Path)
			}
		}
		for _, group := range committed.Rotations {
			for _, blob := range []gitresource.Blob{group.Transition, group.From, group.To} {
				targets = append(targets, blob.Path)
				dependencies = append(dependencies, blob.Path)
			}
		}
		guard, err := tree.GuardMutationInputs(cmd.Context(), targets, editable)
		if err != nil {
			return err
		}
		validator := tombstate.MutationValidator(verified.Manifest.Proclamation.Fingerprint, candidate.Rotations)
		if err := transaction.Execute(cmd.Context(), tree, guard, posts, func(view transaction.View) error { return validator(view) }, transaction.Options{Dependencies: dependencies}); err != nil {
			return err
		}
		return a.success(map[string]any{"generation": verified.Decree.Generation + 1}, func(w io.Writer) error {
			_, e := fmt.Fprintf(w, "Signed decree generation %d\n", verified.Decree.Generation+1)
			return e
		}, nil)
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "explicit tomb worktree")
	_ = cmd.MarkFlagRequired("tomb")
	return cmd
}
func pathMode(root, path string) (os.FileMode, error) {
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return 0, err
	}
	return info.Mode().Perm(), nil
}

func newDecreeValidate(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "validate --tomb TOMB", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		content, configured, _, err := resolveTombContent(cmd, a, tomb)
		if err != nil {
			return err
		}
		var verified *tombstate.Verified
		if configured == nil {
			verified, err = tombstate.VerifyCurrent(content)
		} else {
			verified, err = tombstate.Verify(content, configured.Lock.ProclamationFingerprint)
			if err == nil && verified.Decree.Generation != configured.Lock.DecreeGeneration {
				err = fmt.Errorf("signed decree generation does not match project lock")
			}
		}
		if err != nil {
			return err
		}
		return a.success(map[string]any{"generation": verified.Decree.Generation, "valid": true}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Decree is valid"); return e }, nil)
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "tomb alias or reference")
	return cmd
}
func newDecreeShow(a *app) *cobra.Command {
	var tomb string
	var unverified bool
	cmd := &cobra.Command{Use: "show --tomb TOMB [--unverified]", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		content, configured, _, err := resolveTombContent(cmd, a, tomb)
		if err != nil {
			return err
		}
		warnings := []cliresult.Warning{}
		if !unverified {
			if configured == nil {
				_, err = tombstate.VerifyCurrent(content)
			} else {
				var verified *tombstate.Verified
				verified, err = tombstate.Verify(content, configured.Lock.ProclamationFingerprint)
				if err == nil && verified.Decree.Generation != configured.Lock.DecreeGeneration {
					err = fmt.Errorf("signed decree generation does not match project lock")
				}
			}
			if err != nil {
				return err
			}
		} else {
			warnings = append(warnings, cliresult.Warning{Code: "unverified_decree", Message: "decree bytes have not been signature verified"})
		}
		return a.success(map[string]any{"decree": string(content.Decree.Data), "verified": !unverified}, func(w io.Writer) error { _, e := w.Write(content.Decree.Data); return e }, warnings)
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "tomb alias or reference")
	cmd.Flags().BoolVar(&unverified, "unverified", false, "show decree without signature verification")
	return cmd
}
