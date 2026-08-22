package tombstate

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sort"

	"github.com/marksisson/sphinx/internal/artifactmutation"
	"github.com/marksisson/sphinx/internal/decree"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/hybridsign"
	"github.com/marksisson/sphinx/internal/managedpath"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/marksisson/sphinx/internal/worktree"
)

// MutationBuilder is the concrete Phase 5 signed-state builder used by every
// ordinary artifact/schema mutation. It increments generation exactly once,
// regenerates exhaustive locks from the complete virtual worktree, and signs
// exact decree bytes under the current manifest.
type MutationBuilder struct {
	signing       *hybridsign.PrivateBundle
	current       *decree.Document
	manifestBytes []byte
	rotations     map[int]gitresource.RotationBlobs
}

func NewMutationBuilder(content *gitresource.Content, pinnedFingerprint string, signing *hybridsign.PrivateBundle) (*MutationBuilder, error) {
	if signing == nil {
		return nil, fmt.Errorf("proclamation signing identity is required")
	}
	verified, err := Verify(content, pinnedFingerprint)
	if err != nil {
		return nil, err
	}
	fingerprint, err := signing.Public().Fingerprint()
	if err != nil {
		return nil, err
	}
	if fingerprint != verified.Manifest.Proclamation.Fingerprint {
		return nil, fmt.Errorf("proclamation signing identity does not match the tomb manifest")
	}
	return &MutationBuilder{signing: signing, current: verified.Decree, manifestBytes: append([]byte(nil), content.Manifest.Data...), rotations: content.Rotations}, nil
}

func ApplyMutation(ctx context.Context, tree *worktree.Worktree, changes map[string]transaction.PostImage, builder *MutationBuilder, options transaction.Options) error {
	if builder == nil {
		return fmt.Errorf("authenticated mutation builder is required")
	}
	return artifactmutation.Apply(ctx, tree, changes, builder, builder.Validator(), options)
}

func (b *MutationBuilder) Validator() artifactmutation.Validator {
	if b == nil || b.current == nil {
		return func(artifactmutation.View) error { return fmt.Errorf("authenticated mutation builder is unavailable") }
	}
	return MutationValidator(b.currentFingerprint(), b.rotations)
}

func (b *MutationBuilder) currentFingerprint() string {
	manifest, err := DecodeManifest(b.manifestBytes)
	if err != nil {
		return ""
	}
	return manifest.Proclamation.Fingerprint
}

func (b *MutationBuilder) Dependencies(view artifactmutation.View) ([]string, error) {
	entries, err := view.ManagedPaths()
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(entries)+1+len(b.rotations)*3)
	paths = append(paths, ".tomb/tomb.yaml")
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	sequences := make([]int, 0, len(b.rotations))
	for sequence := range b.rotations {
		sequences = append(sequences, sequence)
	}
	sort.Ints(sequences)
	for _, sequence := range sequences {
		group := b.rotations[sequence]
		for _, blob := range []gitresource.Blob{group.Transition, group.From, group.To} {
			if blob.Path == "" {
				return nil, fmt.Errorf("rotation sequence %08d has an empty dependency path", sequence)
			}
			paths = append(paths, blob.Path)
		}
	}
	return paths, nil
}

func (b *MutationBuilder) Build(view artifactmutation.View) (artifactmutation.SignedState, error) {
	if b == nil || b.current == nil || b.signing == nil {
		return artifactmutation.SignedState{}, fmt.Errorf("authenticated mutation builder is unavailable")
	}
	manifestBytes, _, exists, err := view.Read(".tomb/tomb.yaml")
	if err != nil || !exists {
		return artifactmutation.SignedState{}, fmt.Errorf("read tomb manifest: %w", missing(err, exists))
	}
	if !bytes.Equal(manifestBytes, b.manifestBytes) {
		return artifactmutation.SignedState{}, fmt.Errorf("tomb manifest changed after mutation authorization")
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return artifactmutation.SignedState{}, err
	}
	current := *b.current
	if current.Generation == math.MaxUint64 {
		return artifactmutation.SignedState{}, fmt.Errorf("decree generation overflow")
	}
	artifacts, schemas, err := blobsFromView(view)
	if err != nil {
		return artifactmutation.SignedState{}, err
	}
	current.Generation++
	current.ArtifactLocks, current.SchemaLocks = Locks(artifacts, schemas)
	encoded, err := decree.Encode(current)
	if err != nil {
		return artifactmutation.SignedState{}, err
	}
	signature, err := EncodeDecreeSignature(manifestBytes, encoded, *manifest, b.signing)
	if err != nil {
		return artifactmutation.SignedState{}, err
	}
	return artifactmutation.SignedState{Decree: encoded, Signature: signature}, nil
}

// MutationValidator verifies signature, policy, and exhaustive locks over a
// virtual or installed transaction view. Rotation blobs are immutable inputs
// for ordinary mutations.
func MutationValidator(pinnedFingerprint string, rotations map[int]gitresource.RotationBlobs) artifactmutation.Validator {
	return func(view artifactmutation.View) error {
		manifest, _, manifestExists, err := view.Read(".tomb/tomb.yaml")
		if err != nil || !manifestExists {
			return fmt.Errorf("read tomb manifest: %w", missing(err, manifestExists))
		}
		decreeBytes, _, decreeExists, err := view.Read(artifactmutation.DecreePath)
		if err != nil || !decreeExists {
			return fmt.Errorf("read decree: %w", missing(err, decreeExists))
		}
		signature, _, signatureExists, err := view.Read(artifactmutation.SignaturePath)
		if err != nil || !signatureExists {
			return fmt.Errorf("read decree signature: %w", missing(err, signatureExists))
		}
		artifacts, schemas, err := blobsFromView(view)
		if err != nil {
			return err
		}
		_, err = Verify(&gitresource.Content{Artifacts: artifacts, Schemas: schemas, Rotations: rotations, Manifest: gitresource.Blob{Data: manifest}, Decree: gitresource.Blob{Data: decreeBytes}, Signature: gitresource.Blob{Data: signature}}, pinnedFingerprint)
		return err
	}
}

func blobsFromView(view artifactmutation.View) (map[string]gitresource.Blob, map[string]gitresource.Blob, error) {
	paths, err := view.ManagedPaths()
	if err != nil {
		return nil, nil, err
	}
	artifacts := map[string]gitresource.Blob{}
	schemas := map[string]gitresource.Blob{}
	for _, entry := range paths {
		data, _, exists, err := view.Read(entry.Path)
		if err != nil {
			return nil, nil, err
		}
		if !exists {
			return nil, nil, fmt.Errorf("managed path %q disappeared from transaction view", entry.Path)
		}
		blob := gitresource.Blob{Path: entry.Path, Data: data}
		switch entry.Kind {
		case managedpath.Artifact:
			artifacts[entry.Key] = blob
		case managedpath.Schema:
			schemas[entry.Key] = blob
		}
	}
	return artifacts, schemas, nil
}

func missing(err error, exists bool) error {
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("path does not exist")
	}
	return nil
}
