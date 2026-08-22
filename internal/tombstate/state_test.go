package tombstate

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/decree"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/hybridage"
	"github.com/marksisson/sphinx/internal/hybridsign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
)

const testTombID = "123e4567-e89b-42d3-a456-426614174000"

type bundle struct {
	manifest Manifest
	age      *age.HybridIdentity
	signing  *hybridsign.PrivateBundle
}

func newBundle(t *testing.T, fill byte) bundle {
	t.Helper()
	ageIdentity, err := hybridage.IdentityFromSeed(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signing, err := hybridsign.NewPrivate(bytes.Repeat([]byte{fill + 1}, 32), bytes.Repeat([]byte{fill + 2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	ed, ml := public.Encoded()
	fingerprint, _ := public.Fingerprint()
	salt := proclamation.Salt{}
	for index := range salt {
		salt[index] = fill
	}
	return bundle{manifest: Manifest{Version: 1, TombID: testTombID, Proclamation: Proclamation{KDF: proclamation.KDFSuite, Salt: salt.String(), AgeSuite: hybridage.Suite, AgeRecipient: hybridage.Recipient(ageIdentity), SignatureSuite: hybridsign.Suite, PublicKey: PublicKey{Ed25519: ed, MLDSA65: ml}, Fingerprint: fingerprint}}, age: ageIdentity, signing: signing}
}

func signedContent(t *testing.T, b bundle, generation uint64, ruleName string) *gitresource.Content {
	t.Helper()
	definition := schema.Definition{Version: 1, Name: "credential", Secrets: []schema.Field{{Name: "token", Type: "string", Required: true, Prompt: "Token"}}}
	encrypted, err := (artifact.Engine{}).Create(artifact.Document{Format: 1, Schema: "credential/v1", Inscriptions: map[string]any{}, Secrets: map[string]any{"token": "value"}}, definition, b.manifest.Proclamation.AgeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	artifactBlob := gitresource.Blob{Path: "production/api/artifact.yaml", Data: encrypted}
	schemaBlob := gitresource.Blob{Path: ".tomb/schemas/credential/v1.yaml", Data: []byte("version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n")}
	artifacts := map[string]gitresource.Blob{"production/api": artifactBlob}
	schemas := map[string]gitresource.Blob{"credential/v1": schemaBlob}
	artifactLocks, schemaLocks := Locks(artifacts, schemas)
	rules := []decree.Rule{}
	if ruleName != "" {
		rules = append(rules, decree.Rule{Name: ruleName, Seekers: decree.Selectors{Logins: []string{"alice@example.com"}, Tags: []string{}}, Artifacts: []string{"production/**"}})
	}
	document := decree.Document{Version: 1, Generation: generation, ArtifactLocks: artifactLocks, SchemaLocks: schemaLocks, Rules: rules}
	decreeBytes, err := decree.Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := EncodeManifest(b.manifest)
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes, err := EncodeDecreeSignature(manifestBytes, decreeBytes, b.manifest, b.signing)
	if err != nil {
		t.Fatal(err)
	}
	return &gitresource.Content{Artifacts: artifacts, Schemas: schemas, Rotations: map[int]gitresource.RotationBlobs{}, Manifest: gitresource.Blob{Path: ".tomb/tomb.yaml", Data: manifestBytes}, Decree: gitresource.Blob{Path: ".tomb/decree.yaml", Data: decreeBytes}, Signature: gitresource.Blob{Path: ".tomb/decree.yaml.sig", Data: signatureBytes}}
}

func TestVerifySignatureBeforePolicyAndExhaustiveLocks(t *testing.T) {
	b := newBundle(t, 1)
	defer b.signing.Destroy()
	content := signedContent(t, b, 1, "operators")
	verified, err := Verify(content, b.manifest.Proclamation.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Decree.Generation != 1 {
		t.Fatalf("generation = %d", verified.Decree.Generation)
	}

	tampered := *content
	tampered.Decree.Data = append([]byte(nil), content.Decree.Data...)
	tampered.Decree.Data[20] ^= 1
	if _, err := Verify(&tampered, b.manifest.Proclamation.Fingerprint); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("decree tamper = %v", err)
	}
	missing := *content
	missing.Artifacts = map[string]gitresource.Blob{}
	if _, err := Verify(&missing, b.manifest.Proclamation.Fingerprint); err == nil || !strings.Contains(err.Error(), "exhaustive") {
		t.Fatalf("missing artifact = %v", err)
	}
	if _, err := Verify(content, "SHA256:"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("wrong external fingerprint accepted")
	}
}

func TestCrossSignedRotationChain(t *testing.T) {
	old := newBundle(t, 10)
	defer old.signing.Destroy()
	next := newBundle(t, 20)
	defer next.signing.Destroy()
	content := signedContent(t, next, 2, "operators")
	transition := Transition{Version: 1, Sequence: 1, TombID: testTombID,
		From: TransitionSigning{SignatureSuite: old.manifest.Proclamation.SignatureSuite, PublicKey: old.manifest.Proclamation.PublicKey, Fingerprint: old.manifest.Proclamation.Fingerprint},
		To:   TransitionReplacement{KDF: next.manifest.Proclamation.KDF, Salt: next.manifest.Proclamation.Salt, AgeSuite: next.manifest.Proclamation.AgeSuite, AgeRecipient: next.manifest.Proclamation.AgeRecipient, SignatureSuite: next.manifest.Proclamation.SignatureSuite, PublicKey: next.manifest.Proclamation.PublicKey, Fingerprint: next.manifest.Proclamation.Fingerprint}}
	payload, err := EncodeTransition(transition)
	if err != nil {
		t.Fatal(err)
	}
	from, err := EncodeTransitionSignature(payload, transition, hybridsign.RotationFromPurpose, old.signing)
	if err != nil {
		t.Fatal(err)
	}
	to, err := EncodeTransitionSignature(payload, transition, hybridsign.RotationToPurpose, next.signing)
	if err != nil {
		t.Fatal(err)
	}
	content.Rotations[1] = gitresource.RotationBlobs{Transition: gitresource.Blob{Data: payload}, From: gitresource.Blob{Data: from}, To: gitresource.Blob{Data: to}}
	if _, err := Verify(content, old.manifest.Proclamation.Fingerprint); err != nil {
		t.Fatal(err)
	}

	final := newBundle(t, 30)
	defer final.signing.Destroy()
	multi := signedContent(t, final, 3, "operators")
	multi.Rotations[1] = content.Rotations[1]
	second := Transition{Version: 1, Sequence: 2, TombID: testTombID,
		From: TransitionSigning{SignatureSuite: next.manifest.Proclamation.SignatureSuite, PublicKey: next.manifest.Proclamation.PublicKey, Fingerprint: next.manifest.Proclamation.Fingerprint},
		To:   TransitionReplacement{KDF: final.manifest.Proclamation.KDF, Salt: final.manifest.Proclamation.Salt, AgeSuite: final.manifest.Proclamation.AgeSuite, AgeRecipient: final.manifest.Proclamation.AgeRecipient, SignatureSuite: final.manifest.Proclamation.SignatureSuite, PublicKey: final.manifest.Proclamation.PublicKey, Fingerprint: final.manifest.Proclamation.Fingerprint}}
	secondPayload, err := EncodeTransition(second)
	if err != nil {
		t.Fatal(err)
	}
	secondFrom, err := EncodeTransitionSignature(secondPayload, second, hybridsign.RotationFromPurpose, next.signing)
	if err != nil {
		t.Fatal(err)
	}
	secondTo, err := EncodeTransitionSignature(secondPayload, second, hybridsign.RotationToPurpose, final.signing)
	if err != nil {
		t.Fatal(err)
	}
	multi.Rotations[2] = gitresource.RotationBlobs{Transition: gitresource.Blob{Data: secondPayload}, From: gitresource.Blob{Data: secondFrom}, To: gitresource.Blob{Data: secondTo}}
	if _, err := Verify(multi, old.manifest.Proclamation.Fingerprint); err != nil {
		t.Fatalf("multi-rotation chain: %v", err)
	}

	broken := *content
	broken.Rotations = map[int]gitresource.RotationBlobs{1: content.Rotations[1]}
	item := broken.Rotations[1]
	item.To.Data = append([]byte(nil), item.To.Data...)
	item.To.Data[30] ^= 1
	broken.Rotations[1] = item
	if _, err := Verify(&broken, old.manifest.Proclamation.Fingerprint); err == nil {
		t.Fatal("singly valid rotation accepted")
	}
	delete(broken.Rotations, 1)
	broken.Rotations[2] = content.Rotations[1]
	if _, err := Verify(&broken, old.manifest.Proclamation.Fingerprint); err == nil {
		t.Fatal("reordered/non-contiguous rotation accepted")
	}
}

func TestAdvanceLockGenerationRules(t *testing.T) {
	b := newBundle(t, 30)
	defer b.signing.Destroy()
	currentContent := signedContent(t, b, 4, "operators")
	current := config.Lock{Commit: strings.Repeat("a", 40), ProclamationFingerprint: b.manifest.Proclamation.Fingerprint, DecreeGeneration: 4, LockedAt: time.Unix(1, 0).UTC()}
	now := time.Unix(2, 0).UTC()
	candidate := signedContent(t, b, 5, "operators")
	lock, err := AdvanceLock(current, currentContent, candidate, strings.Repeat("b", 40), now)
	if err != nil {
		t.Fatal(err)
	}
	if lock.DecreeGeneration != 5 || !lock.LockedAt.Equal(now) {
		t.Fatalf("advanced lock = %#v", lock)
	}
	stale := signedContent(t, b, 3, "operators")
	if _, err := AdvanceLock(current, currentContent, stale, strings.Repeat("b", 40), now); err == nil {
		t.Fatal("old generation accepted")
	}
	substitution := signedContent(t, b, 4, "other")
	if _, err := AdvanceLock(current, currentContent, substitution, strings.Repeat("b", 40), now); err == nil {
		t.Fatal("same-generation substitution accepted")
	}
	identical := *currentContent
	if _, err := AdvanceLock(current, currentContent, &identical, strings.Repeat("b", 40), now); err != nil {
		t.Fatalf("identical same-generation state rejected: %v", err)
	}
}
