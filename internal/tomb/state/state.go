// Package state verifies proclamation-signed tomb manifests, decrees,
// exhaustive blob locks, and append-only proclamation trust transitions.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/decree"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	hybridsign "github.com/marksisson/sphinx/internal/hybrid/sign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	yamlstrict "github.com/marksisson/sphinx/internal/yaml/strict"
)

const Version = 1

var tombIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type PublicKey struct {
	Ed25519 string `yaml:"ed25519"`
	MLDSA65 string `yaml:"ml_dsa_65"`
}

type Proclamation struct {
	KDF            string    `yaml:"kdf"`
	Salt           string    `yaml:"salt"`
	AgeSuite       string    `yaml:"age_suite"`
	AgeRecipient   string    `yaml:"age_recipient"`
	SignatureSuite string    `yaml:"signature_suite"`
	PublicKey      PublicKey `yaml:"public_key"`
	Fingerprint    string    `yaml:"fingerprint"`
}

type Manifest struct {
	Version      int          `yaml:"version"`
	TombID       string       `yaml:"tomb_id"`
	Proclamation Proclamation `yaml:"proclamation"`
}

type SignatureComponents struct {
	Ed25519 string `yaml:"ed25519"`
	MLDSA65 string `yaml:"ml_dsa_65"`
}

type DecreeSignature struct {
	Version        int                 `yaml:"version"`
	TombID         string              `yaml:"tomb_id"`
	KeyFingerprint string              `yaml:"key_fingerprint"`
	ManifestSHA256 string              `yaml:"manifest_sha256"`
	Signatures     SignatureComponents `yaml:"signatures"`
}

type TransitionSigning struct {
	SignatureSuite string    `yaml:"signature_suite"`
	PublicKey      PublicKey `yaml:"public_key"`
	Fingerprint    string    `yaml:"fingerprint"`
}

type TransitionReplacement struct {
	KDF            string    `yaml:"kdf"`
	Salt           string    `yaml:"salt"`
	AgeSuite       string    `yaml:"age_suite"`
	AgeRecipient   string    `yaml:"age_recipient"`
	SignatureSuite string    `yaml:"signature_suite"`
	PublicKey      PublicKey `yaml:"public_key"`
	Fingerprint    string    `yaml:"fingerprint"`
}

type Transition struct {
	Version  int                   `yaml:"version"`
	Sequence uint64                `yaml:"sequence"`
	TombID   string                `yaml:"tomb_id"`
	From     TransitionSigning     `yaml:"from"`
	To       TransitionReplacement `yaml:"to"`
}

type TransitionSignature struct {
	Version        int                 `yaml:"version"`
	Sequence       uint64              `yaml:"sequence"`
	TombID         string              `yaml:"tomb_id"`
	KeyFingerprint string              `yaml:"key_fingerprint"`
	PayloadSHA256  string              `yaml:"payload_sha256"`
	Purpose        string              `yaml:"purpose"`
	Signatures     SignatureComponents `yaml:"signatures"`
}

type Verified struct {
	Manifest *Manifest
	Decree   *decree.Document
}

func EncodeManifest(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return yamlstrict.Marshal(manifest)
}

func DecodeManifest(data []byte) (*Manifest, error) {
	var manifest Manifest
	if err := yamlstrict.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse tomb manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (m Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("unsupported tomb manifest version %d", m.Version)
	}
	if !tombIDPattern.MatchString(m.TombID) {
		return fmt.Errorf("tomb ID must be a lowercase UUIDv4")
	}
	return proclamation.ValidatePublic(m.Proclamation.bundle())
}

func (p Proclamation) bundle() proclamation.PublicBundle {
	return proclamation.PublicBundle{KDF: p.KDF, Salt: p.Salt, AgeSuite: p.AgeSuite, AgeRecipient: p.AgeRecipient, SignatureSuite: p.SignatureSuite, SigningPublic: proclamation.SigningPublic{Ed25519: p.PublicKey.Ed25519, MLDSA65: p.PublicKey.MLDSA65}, Fingerprint: p.Fingerprint}
}

func public(signing TransitionSigning) (hybridsign.PublicBundle, error) {
	if signing.SignatureSuite != hybridsign.Suite {
		return hybridsign.PublicBundle{}, fmt.Errorf("transition signature suite %q is unsupported", signing.SignatureSuite)
	}
	return hybridsign.ParsePublicBundle(signing.PublicKey.Ed25519, signing.PublicKey.MLDSA65, signing.Fingerprint)
}

// Verify authenticates the exact decree bytes before parsing policy and then
// validates every exhaustive committed Git-blob lock.
func Verify(content *gitresource.Content, pinnedFingerprint string) (*Verified, error) {
	if content == nil {
		return nil, fmt.Errorf("tomb content is unavailable")
	}
	manifest, err := DecodeManifest(content.Manifest.Data)
	if err != nil {
		return nil, err
	}
	if err := verifyRotationChain(content, pinnedFingerprint, manifest); err != nil {
		return nil, err
	}
	if err := verifyDecreeSignature(content, manifest); err != nil {
		return nil, err
	}
	document, err := decree.Decode(content.Decree.Data)
	if err != nil {
		return nil, err
	}
	if err := VerifyLocks(document, content); err != nil {
		return nil, err
	}
	if err := verifyPublicArtifacts(content, manifest.Proclamation.AgeRecipient); err != nil {
		return nil, err
	}
	return &Verified{Manifest: manifest, Decree: document}, nil
}

// VerifyCurrent verifies a self-consistent tomb for initial enrollment. The
// returned fingerprint still requires explicit caller trust approval.
func VerifyCurrent(content *gitresource.Content) (*Verified, error) {
	manifest, err := DecodeManifest(content.Manifest.Data)
	if err != nil {
		return nil, err
	}
	return Verify(content, manifest.Proclamation.Fingerprint)
}

func verifyDecreeSignature(content *gitresource.Content, manifest *Manifest) error {
	var envelope DecreeSignature
	if err := yamlstrict.Unmarshal(content.Signature.Data, &envelope); err != nil {
		return fmt.Errorf("parse decree signature: %w", err)
	}
	manifestDigest := sha256.Sum256(content.Manifest.Data)
	if envelope.Version != Version || envelope.TombID != manifest.TombID || envelope.KeyFingerprint != manifest.Proclamation.Fingerprint || envelope.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) {
		return fmt.Errorf("decree signature metadata does not match the tomb manifest")
	}
	publicKey, err := hybridsign.ParsePublicBundle(manifest.Proclamation.PublicKey.Ed25519, manifest.Proclamation.PublicKey.MLDSA65, manifest.Proclamation.Fingerprint)
	if err != nil {
		return err
	}
	signature, err := hybridsign.ParseSignature(envelope.Signatures.Ed25519, envelope.Signatures.MLDSA65)
	if err != nil {
		return err
	}
	if err := publicKey.Verify(hybridsign.DecreePurpose, manifest.TombID, manifestDigest[:], content.Decree.Data, signature); err != nil {
		return fmt.Errorf("verify decree signature: %w", err)
	}
	return nil
}

func verifyPublicArtifacts(content *gitresource.Content, proclamationRecipient string) error {
	definitions := make(map[string]*schema.Definition, len(content.Schemas))
	for reference, blob := range content.Schemas {
		definition, err := schema.Decode(blob.Data)
		if err != nil {
			return fmt.Errorf("decode locked schema %q: %w", reference, err)
		}
		if definition.Reference() != reference {
			return fmt.Errorf("locked schema %q declares %q", reference, definition.Reference())
		}
		definitions[reference] = definition
	}
	engine := artifact.Engine{}
	for chamberName, blob := range content.Artifacts {
		inspection, err := engine.Inspect(blob.Data, proclamationRecipient)
		if err != nil {
			return fmt.Errorf("inspect locked artifact %q: %w", chamberName, err)
		}
		if _, exists := definitions[inspection.Schema]; !exists {
			return fmt.Errorf("locked artifact %q references absent schema %q", chamberName, inspection.Schema)
		}
	}
	return nil
}

func VerifyLocks(document *decree.Document, content *gitresource.Content) error {
	if len(document.ArtifactLocks) != len(content.Artifacts) {
		return fmt.Errorf("decree artifact locks are not exhaustive")
	}
	for _, lock := range document.ArtifactLocks {
		blob, exists := content.Artifacts[lock.Chamber]
		if !exists || blob.SHA256Hex() != lock.SHA256 {
			return fmt.Errorf("artifact lock digest mismatch for chamber %q", lock.Chamber)
		}
	}
	if len(document.SchemaLocks) != len(content.Schemas) {
		return fmt.Errorf("decree schema locks are not exhaustive")
	}
	for _, lock := range document.SchemaLocks {
		blob, exists := content.Schemas[lock.Schema]
		if !exists || blob.SHA256Hex() != lock.SHA256 {
			return fmt.Errorf("schema lock digest mismatch for %q", lock.Schema)
		}
	}
	return nil
}

func EncodeDecreeSignature(manifestBytes, decreeBytes []byte, manifest Manifest, signing *hybridsign.PrivateBundle) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	signature, err := signing.Sign(hybridsign.DecreePurpose, manifest.TombID, manifestDigest[:], decreeBytes)
	if err != nil {
		return nil, err
	}
	ed, ml := signature.Encoded()
	envelope := DecreeSignature{Version: Version, TombID: manifest.TombID, KeyFingerprint: manifest.Proclamation.Fingerprint, ManifestSHA256: hex.EncodeToString(manifestDigest[:]), Signatures: SignatureComponents{Ed25519: ed, MLDSA65: ml}}
	return yamlstrict.Marshal(envelope)
}

func EncodeTransition(transition Transition) ([]byte, error) {
	if transition.Version != Version || transition.Sequence == 0 || !tombIDPattern.MatchString(transition.TombID) {
		return nil, fmt.Errorf("transition metadata is invalid")
	}
	if _, err := public(transition.From); err != nil {
		return nil, err
	}
	if err := validateReplacement(transition.To); err != nil {
		return nil, err
	}
	return yamlstrict.Marshal(transition)
}

func EncodeTransitionSignature(transitionBytes []byte, transition Transition, purpose hybridsign.Purpose, signing *hybridsign.PrivateBundle) ([]byte, error) {
	var fingerprint string
	switch purpose {
	case hybridsign.RotationFromPurpose:
		fingerprint = transition.From.Fingerprint
	case hybridsign.RotationToPurpose:
		fingerprint = transition.To.Fingerprint
	default:
		return nil, fmt.Errorf("transition signature purpose is unsupported")
	}
	signature, err := signing.Sign(purpose, transition.TombID, nil, transitionBytes)
	if err != nil {
		return nil, err
	}
	ed, ml := signature.Encoded()
	digest := sha256.Sum256(transitionBytes)
	return yamlstrict.Marshal(TransitionSignature{Version: Version, Sequence: transition.Sequence, TombID: transition.TombID, KeyFingerprint: fingerprint, PayloadSHA256: hex.EncodeToString(digest[:]), Purpose: string(purpose), Signatures: SignatureComponents{Ed25519: ed, MLDSA65: ml}})
}

func verifyRotationChain(content *gitresource.Content, pinned string, manifest *Manifest) error {
	if pinned == "" {
		return fmt.Errorf("trusted proclamation fingerprint is required")
	}
	current := ""
	pinSeen := pinned == manifest.Proclamation.Fingerprint && len(content.Rotations) == 0
	for sequence := 1; sequence <= len(content.Rotations); sequence++ {
		blobs, exists := content.Rotations[sequence]
		if !exists {
			return fmt.Errorf("proclamation rotation chain is non-contiguous")
		}
		var transition Transition
		if err := yamlstrict.Unmarshal(blobs.Transition.Data, &transition); err != nil {
			return fmt.Errorf("parse proclamation rotation %08d: %w", sequence, err)
		}
		if transition.Version != Version || transition.Sequence != uint64(sequence) || transition.TombID != manifest.TombID {
			return fmt.Errorf("proclamation rotation %08d metadata is invalid", sequence)
		}
		fromPublic, err := public(transition.From)
		if err != nil {
			return err
		}
		toSigning := TransitionSigning{SignatureSuite: transition.To.SignatureSuite, PublicKey: transition.To.PublicKey, Fingerprint: transition.To.Fingerprint}
		toPublic, err := public(toSigning)
		if err != nil {
			return err
		}
		if err := validateReplacement(transition.To); err != nil {
			return err
		}
		if sequence > 1 && transition.From.Fingerprint != current {
			return fmt.Errorf("proclamation rotation %08d disconnects the fingerprint chain", sequence)
		}
		if transition.From.Fingerprint == pinned || transition.To.Fingerprint == pinned {
			pinSeen = true
		}
		if err := verifyTransitionEnvelope(blobs.From.Data, transition, blobs.Transition.Data, string(hybridsign.RotationFromPurpose), transition.From.Fingerprint, fromPublic); err != nil {
			return fmt.Errorf("rotation %08d from-signature: %w", sequence, err)
		}
		if err := verifyTransitionEnvelope(blobs.To.Data, transition, blobs.Transition.Data, string(hybridsign.RotationToPurpose), transition.To.Fingerprint, toPublic); err != nil {
			return fmt.Errorf("rotation %08d to-signature: %w", sequence, err)
		}
		current = transition.To.Fingerprint
		if sequence == len(content.Rotations) && !replacementMatchesManifest(transition.To, manifest.Proclamation) {
			return fmt.Errorf("proclamation rotation chain does not end at the tomb manifest")
		}
	}
	if len(content.Rotations) == 0 && pinned != manifest.Proclamation.Fingerprint {
		return fmt.Errorf("locked proclamation fingerprint does not match the tomb manifest")
	}
	if len(content.Rotations) > 0 && !pinSeen {
		return fmt.Errorf("locked proclamation fingerprint is absent from the rotation chain")
	}
	return nil
}

func validateReplacement(value TransitionReplacement) error {
	return proclamation.ValidatePublic(proclamation.PublicBundle{KDF: value.KDF, Salt: value.Salt, AgeSuite: value.AgeSuite, AgeRecipient: value.AgeRecipient, SignatureSuite: value.SignatureSuite, SigningPublic: proclamation.SigningPublic{Ed25519: value.PublicKey.Ed25519, MLDSA65: value.PublicKey.MLDSA65}, Fingerprint: value.Fingerprint})
}

func replacementMatchesManifest(value TransitionReplacement, manifest Proclamation) bool {
	return value.KDF == manifest.KDF && value.Salt == manifest.Salt && value.AgeSuite == manifest.AgeSuite && value.AgeRecipient == manifest.AgeRecipient && value.SignatureSuite == manifest.SignatureSuite && value.PublicKey == manifest.PublicKey && value.Fingerprint == manifest.Fingerprint
}

func verifyTransitionEnvelope(data []byte, transition Transition, payload []byte, purpose, fingerprint string, key hybridsign.PublicBundle) error {
	var envelope TransitionSignature
	if err := yamlstrict.Unmarshal(data, &envelope); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if envelope.Version != Version || envelope.Sequence != transition.Sequence || envelope.TombID != transition.TombID || envelope.KeyFingerprint != fingerprint || envelope.PayloadSHA256 != hex.EncodeToString(digest[:]) || envelope.Purpose != purpose {
		return fmt.Errorf("transition signature metadata mismatch")
	}
	signature, err := hybridsign.ParseSignature(envelope.Signatures.Ed25519, envelope.Signatures.MLDSA65)
	if err != nil {
		return err
	}
	return key.Verify(hybridsign.Purpose(purpose), transition.TombID, nil, payload, signature)
}

func EnrollmentLock(content *gitresource.Content, commit string, now time.Time) (config.Lock, error) {
	state, err := VerifyCurrent(content)
	if err != nil {
		return config.Lock{}, err
	}
	lock := config.Lock{Commit: commit, ProclamationFingerprint: state.Manifest.Proclamation.Fingerprint, DecreeGeneration: state.Decree.Generation, LockedAt: now.UTC()}
	if err := lock.Validate(); err != nil {
		return config.Lock{}, err
	}
	return lock, nil
}

// AdvanceLock validates trust from the currently pinned proclamation and
// enforces monotonic generation semantics for a descendant candidate already
// established by the locked-resource resolver.
func AdvanceLock(current config.Lock, currentContent, candidateContent *gitresource.Content, candidateCommit string, now time.Time) (config.Lock, error) {
	currentState, err := Verify(currentContent, current.ProclamationFingerprint)
	if err != nil {
		return config.Lock{}, fmt.Errorf("verify currently locked tomb state: %w", err)
	}
	if currentState.Decree.Generation != current.DecreeGeneration {
		return config.Lock{}, fmt.Errorf("configured decree generation does not match the currently locked tomb")
	}
	candidateState, err := Verify(candidateContent, current.ProclamationFingerprint)
	if err != nil {
		return config.Lock{}, err
	}
	if candidateState.Decree.Generation < current.DecreeGeneration {
		return config.Lock{}, fmt.Errorf("candidate decree generation is a rollback")
	}
	if candidateState.Decree.Generation == current.DecreeGeneration && !sameSignedState(currentContent, candidateContent) {
		return config.Lock{}, fmt.Errorf("candidate substitutes different signed state at the same decree generation")
	}
	lock := config.Lock{Commit: candidateCommit, ProclamationFingerprint: candidateState.Manifest.Proclamation.Fingerprint, DecreeGeneration: candidateState.Decree.Generation, LockedAt: now.UTC()}
	if err := lock.Validate(); err != nil {
		return config.Lock{}, err
	}
	return lock, nil
}

func sameSignedState(left, right *gitresource.Content) bool {
	if left == nil || right == nil || !bytes.Equal(left.Manifest.Data, right.Manifest.Data) || !bytes.Equal(left.Decree.Data, right.Decree.Data) || !bytes.Equal(left.Signature.Data, right.Signature.Data) || len(left.Artifacts) != len(right.Artifacts) || len(left.Schemas) != len(right.Schemas) || len(left.Rotations) != len(right.Rotations) {
		return false
	}
	for name, blob := range left.Artifacts {
		other, ok := right.Artifacts[name]
		if !ok || !bytes.Equal(blob.Data, other.Data) {
			return false
		}
	}
	for name, blob := range left.Schemas {
		other, ok := right.Schemas[name]
		if !ok || !bytes.Equal(blob.Data, other.Data) {
			return false
		}
	}
	for sequence, blobs := range left.Rotations {
		other, ok := right.Rotations[sequence]
		if !ok || !bytes.Equal(blobs.Transition.Data, other.Transition.Data) || !bytes.Equal(blobs.From.Data, other.From.Data) || !bytes.Equal(blobs.To.Data, other.To.Data) {
			return false
		}
	}
	return true
}

func Locks(artifacts map[string]gitresource.Blob, schemas map[string]gitresource.Blob) ([]decree.ArtifactLock, []decree.SchemaLock) {
	artifactNames := make([]string, 0, len(artifacts))
	for name := range artifacts {
		artifactNames = append(artifactNames, name)
	}
	sort.Strings(artifactNames)
	artifactLocks := make([]decree.ArtifactLock, len(artifactNames))
	for index, name := range artifactNames {
		artifactLocks[index] = decree.ArtifactLock{Chamber: name, SHA256: artifacts[name].SHA256Hex()}
	}
	schemaNames := make([]string, 0, len(schemas))
	for name := range schemas {
		schemaNames = append(schemaNames, name)
	}
	sort.Strings(schemaNames)
	schemaLocks := make([]decree.SchemaLock, len(schemaNames))
	for index, name := range schemaNames {
		schemaLocks[index] = decree.SchemaLock{Schema: name, SHA256: schemas[name].SHA256Hex()}
	}
	return artifactLocks, schemaLocks
}
