package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/chamber"
	cliresult "github.com/marksisson/sphinx/internal/cli/result"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/reveal"
	"github.com/marksisson/sphinx/internal/schema"
	lockedresource "github.com/marksisson/sphinx/internal/tomb/lock"
	tombstate "github.com/marksisson/sphinx/internal/tomb/state"
	"github.com/marksisson/sphinx/internal/tomb/transaction"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func newArtifactCommand(a *app) *cobra.Command {
	c := commandGroup("artifact", "Create, inspect, mutate, validate, and reveal artifacts")
	c.AddCommand(newArtifactCreate(a), newArtifactInscription(a), newArtifactReseal(a), newArtifactDelete(a), newArtifactInspect(a), newArtifactReveal(a, false), newArtifactReveal(a, true))
	return c
}
func addPathTomb(cmd *cobra.Command, target *string) {
	cmd.Flags().StringVar(target, "tomb", "", "explicit tomb worktree")
	_ = cmd.MarkFlagRequired("tomb")
}
func builderFor(s *mutationSession) (*tombstate.MutationBuilder, error) {
	return tombstate.NewMutationBuilder(s.content, s.verified.Manifest.Proclamation.Fingerprint, s.derived.SigningIdentity())
}
func promptValues(a *app, fields []schema.Field, only string) (map[string]any, error) {
	terminal, err := a.openTerminal()
	if err != nil {
		return nil, err
	}
	defer terminal.Close()
	values := map[string]any{}
	for _, field := range fields {
		if only != "" && field.Name != only {
			continue
		}
		label := field.Label()
		if field.Type == "enum" {
			label += " (" + strings.Join(field.Values, "/") + ")"
		}
		raw, err := terminal.ReadPassword([]byte(label + ": "))
		if err != nil {
			return nil, err
		}
		text := string(raw)
		clear(raw)
		if text == "" && !field.Required {
			continue
		}
		value, err := schema.ParseValue(field, text)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field.Name, err)
		}
		values[field.Name] = value
	}
	if only != "" {
		if _, ok := values[only]; !ok {
			return nil, fmt.Errorf("field %q is not declared or has no replacement", only)
		}
	}
	return values, nil
}

func newArtifactCreate(a *app) *cobra.Command {
	var tomb, schemaRef string
	cmd := &cobra.Command{Use: "create --tomb path:WORKTREE --schema SCHEMA CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		parsed, err := chamber.Parse(args[0])
		if err != nil {
			return err
		}
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		if _, exists := session.content.Artifacts[parsed.String()]; exists {
			return fmt.Errorf("artifact already exists")
		}
		blob, exists := session.content.Schemas[schemaRef]
		if !exists {
			return fmt.Errorf("schema %q does not exist", schemaRef)
		}
		definition, err := schema.Decode(blob.Data)
		if err != nil {
			return err
		}
		secrets, err := promptValues(a, definition.Secrets, "")
		if err != nil {
			return err
		}
		inscriptions, err := promptValues(a, definition.Inscriptions, "")
		if err != nil {
			return err
		}
		document := artifact.Document{Format: 1, Schema: schemaRef, Secrets: secrets, Inscriptions: inscriptions}
		encrypted, err := (artifact.Engine{}).Create(document, *definition, session.verified.Manifest.Proclamation.AgeRecipient)
		document.Destroy()
		if err != nil {
			return err
		}
		builder, err := builderFor(session)
		if err != nil {
			return err
		}
		path := parsed.ArtifactPath()
		if err := tombstate.ApplyMutation(cmd.Context(), session.tree, map[string]transaction.PostImage{path: {Data: encrypted, Mode: 0o600}}, builder, transaction.Options{}); err != nil {
			return err
		}
		warning := cliresult.Warning{Code: "guardian_required", Message: "artifact has no guardian recipient and cannot be revealed until a guardian is added"}
		return a.success(map[string]any{"chamber": parsed.String(), "schema": schemaRef, "generation": session.verified.Decree.Generation + 1}, func(w io.Writer) error { _, e := fmt.Fprintf(w, "Created artifact %s\n", parsed.String()); return e }, []cliresult.Warning{warning})
	}}
	addPathTomb(cmd, &tomb)
	cmd.Flags().StringVar(&schemaRef, "schema", "", "schema reference")
	_ = cmd.MarkFlagRequired("schema")
	return cmd
}

func existingArtifact(session *mutationSession, chamberText string) (chamber.Path, artifact.Inspection, *schema.Definition, error) {
	parsed, err := chamber.Parse(chamberText)
	if err != nil {
		return chamber.Path{}, artifact.Inspection{}, nil, err
	}
	blob, ok := session.content.Artifacts[parsed.String()]
	if !ok {
		return chamber.Path{}, artifact.Inspection{}, nil, fmt.Errorf("artifact does not exist")
	}
	inspection, err := (artifact.Engine{}).Inspect(blob.Data, session.verified.Manifest.Proclamation.AgeRecipient)
	if err != nil {
		return chamber.Path{}, artifact.Inspection{}, nil, err
	}
	schemaBlob := session.content.Schemas[inspection.Schema]
	definition, err := schema.Decode(schemaBlob.Data)
	return parsed, inspection, definition, err
}
func newArtifactInscription(a *app) *cobra.Command {
	var tomb, name string
	cmd := &cobra.Command{Use: "set-inscription --tomb path:WORKTREE --inscription NAME CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		parsed, _, definition, err := existingArtifact(session, args[0])
		if err != nil {
			return err
		}
		values, err := promptValues(a, definition.Inscriptions, name)
		if err != nil {
			return err
		}
		encrypted, err := (artifact.Engine{}).SetInscription(session.content.Artifacts[parsed.String()].Data, session.derived.AgeIdentity(), *definition, name, values[name])
		if err != nil {
			return err
		}
		builder, err := builderFor(session)
		if err != nil {
			return err
		}
		mode, err := pathMode(session.tree.Root, parsed.ArtifactPath())
		if err != nil {
			return err
		}
		if err := tombstate.ApplyMutation(cmd.Context(), session.tree, map[string]transaction.PostImage{parsed.ArtifactPath(): {Data: encrypted, Mode: mode}}, builder, transaction.Options{}); err != nil {
			return err
		}
		return a.success(map[string]any{"chamber": parsed.String(), "inscription": name, "generation": session.verified.Decree.Generation + 1}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Updated inscription"); return e }, nil)
	}}
	addPathTomb(cmd, &tomb)
	cmd.Flags().StringVar(&name, "inscription", "", "schema inscription name")
	_ = cmd.MarkFlagRequired("inscription")
	return cmd
}
func newArtifactReseal(a *app) *cobra.Command {
	var tomb, selected string
	cmd := &cobra.Command{Use: "reseal --tomb path:WORKTREE [--secret NAME] CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		parsed, _, definition, err := existingArtifact(session, args[0])
		if err != nil {
			return err
		}
		values, err := promptValues(a, definition.Secrets, selected)
		if err != nil {
			return err
		}
		encrypted, err := (artifact.Engine{}).Reseal(session.content.Artifacts[parsed.String()].Data, session.derived.AgeIdentity(), *definition, selected, values)
		if err != nil {
			return err
		}
		builder, err := builderFor(session)
		if err != nil {
			return err
		}
		mode, err := pathMode(session.tree.Root, parsed.ArtifactPath())
		if err != nil {
			return err
		}
		if err := tombstate.ApplyMutation(cmd.Context(), session.tree, map[string]transaction.PostImage{parsed.ArtifactPath(): {Data: encrypted, Mode: mode}}, builder, transaction.Options{}); err != nil {
			return err
		}
		return a.success(map[string]any{"chamber": parsed.String(), "secret": selected, "generation": session.verified.Decree.Generation + 1}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Resealed artifact"); return e }, nil)
	}}
	addPathTomb(cmd, &tomb)
	cmd.Flags().StringVar(&selected, "secret", "", "replace exactly one secret")
	return cmd
}
func newArtifactDelete(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "delete --tomb path:WORKTREE CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		parsed, err := chamber.Parse(args[0])
		if err != nil {
			return err
		}
		if err := a.confirm(fmt.Sprintf("Delete artifact %q? [y/N]: ", parsed.String())); err != nil {
			return err
		}
		session, err := newMutationSession(cmd, a, tomb)
		if err != nil {
			return err
		}
		defer session.destroy()
		if _, ok := session.content.Artifacts[parsed.String()]; !ok {
			return fmt.Errorf("artifact does not exist")
		}
		builder, err := builderFor(session)
		if err != nil {
			return err
		}
		if err := tombstate.ApplyMutation(cmd.Context(), session.tree, map[string]transaction.PostImage{parsed.ArtifactPath(): {Delete: true}}, builder, transaction.Options{}); err != nil {
			return err
		}
		return a.success(map[string]any{"chamber": parsed.String(), "generation": session.verified.Decree.Generation + 1}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Deleted artifact"); return e }, nil)
	}}
	addPathTomb(cmd, &tomb)
	return cmd
}

func newArtifactInspect(a *app) *cobra.Command {
	var tomb string
	cmd := &cobra.Command{Use: "inspect --tomb TOMB CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
		parsed, err := chamber.Parse(args[0])
		if err != nil {
			return err
		}
		blob, ok := content.Artifacts[parsed.String()]
		if !ok {
			return fmt.Errorf("artifact does not exist")
		}
		inspection, err := (artifact.Engine{}).Inspect(blob.Data, verified.Manifest.Proclamation.AgeRecipient)
		if err != nil {
			return err
		}
		data := map[string]any{"chamber": parsed.String(), "format": inspection.Format, "schema": inspection.Schema, "inscriptions": inspection.Inscriptions, "recipient_fingerprints": inspection.RecipientFingerprints, "verified": false}
		warning := cliresult.Warning{Code: inspection.WarningCode, Message: inspection.Warning}
		return a.success(data, func(w io.Writer) error {
			encoded, err := yaml.Marshal(map[string]any{"schema": inspection.Schema, "inscriptions": inspection.Inscriptions, "recipient_fingerprints": inspection.RecipientFingerprints, "verified": false})
			if err != nil {
				return err
			}
			_, err = w.Write(encoded)
			return err
		}, []cliresult.Warning{warning})
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "tomb alias or reference")
	return cmd
}

func newArtifactReveal(a *app, validateOnly bool) *cobra.Command {
	var tomb, selected string
	name := "reveal"
	if validateOnly {
		name = "validate"
	}
	cmd := &cobra.Command{Use: name + " --tomb TOMB [--secret NAME] CHAMBER", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		store, project, cwd, err := projectState(cmd.Context(), a, false)
		_ = store
		if err != nil {
			return err
		}
		alias, configured, err := project.Select(cmd.Context(), tomb, cwd)
		if err != nil {
			return err
		}
		resource, err := (lockedresource.Resolver{Materializer: a.materializer}).Resolve(cmd.Context(), *project, tomb, cwd, args[0])
		if err != nil {
			return err
		}
		document, err := (reveal.Coordinator{Engine: artifact.Engine{}, Seekers: a.seekers, Guardians: a.guardians}).Reveal(cmd.Context(), resource, configured)
		if err != nil {
			return err
		}
		defer document.Destroy()
		if selected != "" {
			if _, ok := document.Secrets[selected]; !ok {
				return fmt.Errorf("secret %q does not exist", selected)
			}
		}
		if validateOnly {
			return a.success(map[string]any{"tomb": alias, "chamber": resource.Chamber.String(), "valid": true}, func(w io.Writer) error { _, e := fmt.Fprintln(w, "Artifact is valid"); return e }, nil)
		}
		if err := a.revealConfirmation(); err != nil {
			return err
		}
		if a.json {
			secrets := document.Secrets
			if selected != "" {
				secrets = map[string]any{selected: document.Secrets[selected]}
			}
			return a.success(map[string]any{"secrets": secrets}, nil, nil)
		}
		if err := emitSecrets(a.out, document, resource.Content, resource.Chamber.String(), selected); err != nil {
			return cliresult.IO("write decrypted stdout", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&tomb, "tomb", "", "project tomb alias or locked reference")
	if !validateOnly {
		cmd.Flags().StringVar(&selected, "secret", "", "reveal exactly one secret")
	}
	return cmd
}

func emitSecrets(w io.Writer, document *artifact.Document, content *gitresource.Content, _ string, selected string) error {
	if selected != "" {
		switch value := document.Secrets[selected].(type) {
		case string:
			_, err := io.WriteString(w, value)
			return err
		case bool:
			_, err := fmt.Fprintf(w, "%t", value)
			return err
		default:
			_, err := fmt.Fprintf(w, "%v", value)
			return err
		}
	}
	node := &yaml.Node{Kind: yaml.MappingNode}
	node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "secrets"})
	mapping := &yaml.Node{Kind: yaml.MappingNode}
	schemaBlob, ok := content.Schemas[document.Schema]
	if !ok {
		return fmt.Errorf("artifact schema is absent")
	}
	definition, err := schema.Decode(schemaBlob.Data)
	if err != nil {
		return err
	}
	for _, field := range definition.Secrets {
		secretValue, exists := document.Secrets[field.Name]
		if !exists {
			continue
		}
		key := &yaml.Node{Kind: yaml.ScalarNode, Value: field.Name}
		value := &yaml.Node{}
		if err := value.Encode(secretValue); err != nil {
			return err
		}
		mapping.Content = append(mapping.Content, key, value)
	}
	node.Content = append(node.Content, mapping)
	return yaml.NewEncoder(w).Encode(node)
}
