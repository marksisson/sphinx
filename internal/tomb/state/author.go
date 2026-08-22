package state

import (
	"fmt"
	"math"

	"github.com/marksisson/sphinx/internal/decree"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	hybridsign "github.com/marksisson/sphinx/internal/hybrid/sign"
)

// SignDraft overwrites editor-visible managed generation/lock fields, validates
// the resulting allow-only policy, and creates its detached proclamation
// signature. previousGeneration zero is reserved for initial default-deny state.
func SignDraft(manifestBytes, draftBytes []byte, previousGeneration uint64, artifacts map[string]gitresource.Blob, schemas map[string]gitresource.Blob, signing *hybridsign.PrivateBundle) ([]byte, []byte, error) {
	if signing == nil {
		return nil, nil, fmt.Errorf("proclamation signing identity is required")
	}
	manifest, err := DecodeManifest(manifestBytes)
	if err != nil {
		return nil, nil, err
	}
	fingerprint, err := signing.Public().Fingerprint()
	if err != nil {
		return nil, nil, err
	}
	if fingerprint != manifest.Proclamation.Fingerprint {
		return nil, nil, fmt.Errorf("proclamation signing identity does not match the tomb manifest")
	}
	if previousGeneration == math.MaxUint64 {
		return nil, nil, fmt.Errorf("decree generation overflow")
	}
	draft, err := decree.DecodeDraft(draftBytes)
	if err != nil {
		return nil, nil, err
	}
	if draft.Version != decree.Version {
		return nil, nil, fmt.Errorf("unsupported decree version %d", draft.Version)
	}
	draft.Version = decree.Version
	draft.Generation = previousGeneration + 1
	draft.ArtifactLocks, draft.SchemaLocks = Locks(artifacts, schemas)
	encoded, err := decree.Encode(*draft)
	if err != nil {
		return nil, nil, err
	}
	signature, err := EncodeDecreeSignature(manifestBytes, encoded, *manifest, signing)
	if err != nil {
		return nil, nil, err
	}
	return encoded, signature, nil
}
