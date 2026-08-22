// Package proclamationrotation performs the all-artifact, cross-signed,
// journaled proclamation trust transition.
package proclamationrotation

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/decree"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/hybridsign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/marksisson/sphinx/internal/worktree"
)

type Keys interface {
	Public() proclamation.PublicBundle
	AgeIdentity() *age.HybridIdentity
	SigningIdentity() *hybridsign.PrivateBundle
}

func Rotate(ctx context.Context, tree *worktree.Worktree, engine artifact.Engine, current *gitresource.Content, oldDerived, newDerived Keys, options transaction.Options) error {
	if tree == nil || current == nil || oldDerived == nil || newDerived == nil {
		return fmt.Errorf("proclamation rotation requires a worktree, current tomb, and both proclamation derivations")
	}
	verified, err := tombstate.VerifyCurrent(current)
	if err != nil {
		return err
	}
	definitions := make(map[string]schema.Definition, len(current.Schemas))
	for reference, blob := range current.Schemas {
		definition, err := schema.Decode(blob.Data)
		if err != nil {
			return fmt.Errorf("decode locked schema %q: %w", reference, err)
		}
		if definition.Reference() != reference {
			return fmt.Errorf("locked schema %q declares %q", reference, definition.Reference())
		}
		definitions[reference] = *definition
	}
	if !samePublic(oldDerived.Public(), verified.Manifest.Proclamation) {
		return fmt.Errorf("current proclamation does not match the tomb manifest")
	}
	if oldDerived.Public().Fingerprint == newDerived.Public().Fingerprint || oldDerived.Public().AgeRecipient == newDerived.Public().AgeRecipient {
		return fmt.Errorf("replacement proclamation must be distinct")
	}

	newManifest := tombstate.Manifest{Version: tombstate.Version, TombID: verified.Manifest.TombID, Proclamation: fromPublic(newDerived.Public())}
	manifestBytes, err := tombstate.EncodeManifest(newManifest)
	if err != nil {
		return err
	}
	posts := make(map[string]transaction.PostImage, len(current.Artifacts)+6)
	candidateArtifacts := make(map[string]gitresource.Blob, len(current.Artifacts))
	for chamberName, blob := range current.Artifacts {
		inspection, err := engine.Inspect(blob.Data, verified.Manifest.Proclamation.AgeRecipient)
		if err != nil {
			return fmt.Errorf("inspect artifact %q: %w", chamberName, err)
		}
		definition, exists := definitions[inspection.Schema]
		if !exists {
			return fmt.Errorf("resolved schema %q is unavailable for artifact %q", inspection.Schema, chamberName)
		}
		encrypted, err := engine.ReplaceProclamation(blob.Data, oldDerived.AgeIdentity(), definition, newManifest.Proclamation.AgeRecipient)
		if err != nil {
			return fmt.Errorf("rotate artifact %q: %w", chamberName, err)
		}
		mode, err := worktreeMode(tree.Root, blob.Path)
		if err != nil {
			return err
		}
		posts[blob.Path] = transaction.PostImage{Data: encrypted, Mode: mode}
		candidateArtifacts[chamberName] = gitresource.Blob{Path: blob.Path, Data: encrypted}
	}
	candidateSchemas := make(map[string]gitresource.Blob, len(current.Schemas))
	for name, blob := range current.Schemas {
		candidateSchemas[name] = blob
	}
	artifactLocks, schemaLocks := tombstate.Locks(candidateArtifacts, candidateSchemas)
	if verified.Decree.Generation == ^uint64(0) {
		return fmt.Errorf("decree generation overflow")
	}
	candidateDecree := *verified.Decree
	candidateDecree.Generation++
	candidateDecree.ArtifactLocks = artifactLocks
	candidateDecree.SchemaLocks = schemaLocks
	decreeBytes, err := decree.Encode(candidateDecree)
	if err != nil {
		return err
	}
	decreeSignature, err := tombstate.EncodeDecreeSignature(manifestBytes, decreeBytes, newManifest, newDerived.SigningIdentity())
	if err != nil {
		return err
	}

	sequence := len(current.Rotations) + 1
	transition := tombstate.Transition{Version: tombstate.Version, Sequence: uint64(sequence), TombID: newManifest.TombID,
		From: tombstate.TransitionSigning{SignatureSuite: verified.Manifest.Proclamation.SignatureSuite, PublicKey: verified.Manifest.Proclamation.PublicKey, Fingerprint: verified.Manifest.Proclamation.Fingerprint},
		To:   tombstate.TransitionReplacement{KDF: newManifest.Proclamation.KDF, Salt: newManifest.Proclamation.Salt, AgeSuite: newManifest.Proclamation.AgeSuite, AgeRecipient: newManifest.Proclamation.AgeRecipient, SignatureSuite: newManifest.Proclamation.SignatureSuite, PublicKey: newManifest.Proclamation.PublicKey, Fingerprint: newManifest.Proclamation.Fingerprint}}
	transitionBytes, err := tombstate.EncodeTransition(transition)
	if err != nil {
		return err
	}
	fromSignature, err := tombstate.EncodeTransitionSignature(transitionBytes, transition, hybridsign.RotationFromPurpose, oldDerived.SigningIdentity())
	if err != nil {
		return err
	}
	toSignature, err := tombstate.EncodeTransitionSignature(transitionBytes, transition, hybridsign.RotationToPurpose, newDerived.SigningIdentity())
	if err != nil {
		return err
	}
	base := fmt.Sprintf(".tomb/rotations/%08d", sequence)
	manifestMode, err := worktreeMode(tree.Root, ".tomb/tomb.yaml")
	if err != nil {
		return err
	}
	decreeMode, err := worktreeMode(tree.Root, ".tomb/decree.yaml")
	if err != nil {
		return err
	}
	signatureMode, err := worktreeMode(tree.Root, ".tomb/decree.yaml.sig")
	if err != nil {
		return err
	}
	posts[".tomb/tomb.yaml"] = transaction.PostImage{Data: manifestBytes, Mode: manifestMode}
	posts[".tomb/decree.yaml"] = transaction.PostImage{Data: decreeBytes, Mode: decreeMode}
	posts[".tomb/decree.yaml.sig"] = transaction.PostImage{Data: decreeSignature, Mode: signatureMode}
	posts[base+".yaml"] = transaction.PostImage{Data: transitionBytes, Mode: 0o600}
	posts[base+".from.sig"] = transaction.PostImage{Data: fromSignature, Mode: 0o600}
	posts[base+".to.sig"] = transaction.PostImage{Data: toSignature, Mode: 0o600}

	candidateRotations := make(map[int]gitresource.RotationBlobs, len(current.Rotations)+1)
	for number, blobs := range current.Rotations {
		candidateRotations[number] = blobs
	}
	candidateRotations[sequence] = gitresource.RotationBlobs{Transition: gitresource.Blob{Path: base + ".yaml", Data: transitionBytes}, From: gitresource.Blob{Path: base + ".from.sig", Data: fromSignature}, To: gitresource.Blob{Path: base + ".to.sig", Data: toSignature}}
	dependencies := make([]string, 0, len(current.Schemas)+len(current.Rotations)*3)
	for _, blob := range current.Schemas {
		dependencies = append(dependencies, blob.Path)
	}
	for _, blobs := range current.Rotations {
		dependencies = append(dependencies, blobs.Transition.Path, blobs.From.Path, blobs.To.Path)
	}
	options.Dependencies = append(options.Dependencies, dependencies...)
	targetSet := map[string]bool{}
	for path := range posts {
		targetSet[path] = true
	}
	for _, path := range options.Dependencies {
		targetSet[path] = true
	}
	targets := make([]string, 0, len(targetSet))
	for path := range targetSet {
		targets = append(targets, path)
	}
	guard, err := tree.GuardMutation(ctx, targets)
	if err != nil {
		return err
	}
	validator := func(view transaction.View) error {
		manifest, _, ok, err := view.Read(".tomb/tomb.yaml")
		if err != nil || !ok {
			return fmt.Errorf("read candidate manifest")
		}
		decreeData, _, ok, err := view.Read(".tomb/decree.yaml")
		if err != nil || !ok {
			return fmt.Errorf("read candidate decree")
		}
		signature, _, ok, err := view.Read(".tomb/decree.yaml.sig")
		if err != nil || !ok {
			return fmt.Errorf("read candidate decree signature")
		}
		artifacts := map[string]gitresource.Blob{}
		schemas := map[string]gitresource.Blob{}
		for name, blob := range candidateArtifacts {
			data, _, exists, err := view.Read(blob.Path)
			if err != nil || !exists {
				return fmt.Errorf("read candidate artifact %q", name)
			}
			artifacts[name] = gitresource.Blob{Path: blob.Path, Data: data}
		}
		for name, blob := range candidateSchemas {
			data, _, exists, err := view.Read(blob.Path)
			if err != nil || !exists {
				return fmt.Errorf("read candidate schema %q", name)
			}
			schemas[name] = gitresource.Blob{Path: blob.Path, Data: data}
		}
		rotations := make(map[int]gitresource.RotationBlobs, len(candidateRotations))
		for number, blobs := range candidateRotations {
			transitionData, _, exists, err := view.Read(blobs.Transition.Path)
			if blobs.Transition.Path == "" && number == sequence {
				transitionData = transitionBytes
				exists = true
				err = nil
			}
			if err != nil || !exists {
				return fmt.Errorf("read rotation %08d", number)
			}
			fromData, _, exists, err := view.Read(blobs.From.Path)
			if blobs.From.Path == "" && number == sequence {
				fromData = fromSignature
				exists = true
				err = nil
			}
			if err != nil || !exists {
				return fmt.Errorf("read rotation %08d from signature", number)
			}
			toData, _, exists, err := view.Read(blobs.To.Path)
			if blobs.To.Path == "" && number == sequence {
				toData = toSignature
				exists = true
				err = nil
			}
			if err != nil || !exists {
				return fmt.Errorf("read rotation %08d to signature", number)
			}
			rotations[number] = gitresource.RotationBlobs{Transition: gitresource.Blob{Data: transitionData}, From: gitresource.Blob{Data: fromData}, To: gitresource.Blob{Data: toData}}
		}
		_, err = tombstate.Verify(&gitresource.Content{Artifacts: artifacts, Schemas: schemas, Rotations: rotations, Manifest: gitresource.Blob{Data: manifest}, Decree: gitresource.Blob{Data: decreeData}, Signature: gitresource.Blob{Data: signature}}, verified.Manifest.Proclamation.Fingerprint)
		return err
	}
	return transaction.Execute(ctx, tree, guard, posts, validator, options)
}

func fromPublic(value proclamation.PublicBundle) tombstate.Proclamation {
	return tombstate.Proclamation{KDF: value.KDF, Salt: value.Salt, AgeSuite: value.AgeSuite, AgeRecipient: value.AgeRecipient, SignatureSuite: value.SignatureSuite, PublicKey: tombstate.PublicKey{Ed25519: value.SigningPublic.Ed25519, MLDSA65: value.SigningPublic.MLDSA65}, Fingerprint: value.Fingerprint}
}
func samePublic(value proclamation.PublicBundle, expected tombstate.Proclamation) bool {
	return fromPublic(value) == expected
}
func worktreeMode(root, path string) (fs.FileMode, error) {
	stat, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return 0, err
	}
	if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("artifact worktree path %q is not a regular file", path)
	}
	return stat.Mode().Perm(), nil
}
