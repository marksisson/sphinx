package reveal

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/chamber"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/decree"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/guardian"
	hybridage "github.com/marksisson/sphinx/internal/hybrid/age"
	hybridsign "github.com/marksisson/sphinx/internal/hybrid/sign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/seeker"
	lockedresource "github.com/marksisson/sphinx/internal/tomb/lock"
	tombstate "github.com/marksisson/sphinx/internal/tomb/state"
)

type fakeSeekers struct {
	identity seeker.Identity
	err      error
	calls    int
}

func (f *fakeSeekers) Resolve(context.Context) (seeker.Identity, error) {
	f.calls++
	return f.identity, f.err
}

type fakeGuardians struct {
	records map[string][]byte
	calls   []string
}

func (f *fakeGuardians) Get(name guardian.Name, provider guardian.Provider) (*guardian.Record, error) {
	f.calls = append(f.calls, string(name))
	data, ok := f.records[string(name)]
	if !ok {
		return nil, fmt.Errorf("missing")
	}
	return guardian.ParseRecord(data)
}

type revealFixture struct {
	resource   *lockedresource.Artifact
	configured config.ProjectTomb
	loader     *fakeGuardians
	signing    *hybridsign.PrivateBundle
}

func makeFixture(t *testing.T, guardianCount int) revealFixture {
	t.Helper()
	proclamationIdentity, err := hybridage.IdentityFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signing, err := hybridsign.NewPrivate(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	ed, ml := public.Encoded()
	fingerprint, _ := public.Fingerprint()
	salt := proclamation.Salt{}
	manifest := tombstate.Manifest{Version: 1, TombID: "123e4567-e89b-42d3-a456-426614174000", Proclamation: tombstate.Proclamation{KDF: proclamation.KDFSuite, Salt: salt.String(), AgeSuite: hybridage.Suite, AgeRecipient: hybridage.Recipient(proclamationIdentity), SignatureSuite: hybridsign.Suite, PublicKey: tombstate.PublicKey{Ed25519: ed, MLDSA65: ml}, Fingerprint: fingerprint}}
	manifestBytes, err := tombstate.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	definition := schema.Definition{Version: 1, Name: "credential", Secrets: []schema.Field{{Name: "token", Type: "string", Required: true, Prompt: "Token"}}}
	schemaBytes := []byte("version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n")
	engine := artifact.Engine{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 512)), Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	encrypted, err := engine.Create(artifact.Document{Format: 1, Schema: "credential/v1", Inscriptions: map[string]any{}, Secrets: map[string]any{"token": "secret"}}, definition, manifest.Proclamation.AgeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	loader := &fakeGuardians{records: map[string][]byte{}}
	selections := []config.GuardianSelection{}
	for index := 0; index < guardianCount; index++ {
		name, _ := guardian.ParseName(fmt.Sprintf("guardian-%d", index))
		record, err := guardian.GenerateRecord(name, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := record.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		loader.records[string(name)] = encoded
		selections = append(selections, config.GuardianSelection{Name: name, Provider: guardian.Environment})
		encrypted, err = engine.AddRecipient(encrypted, proclamationIdentity, definition, record.Recipient())
		record.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}
	artifactBlob := gitresource.Blob{Path: "production/api/artifact.yaml", Data: encrypted}
	schemaBlob := gitresource.Blob{Path: ".tomb/schemas/credential/v1.yaml", Data: schemaBytes}
	artifacts := map[string]gitresource.Blob{"production/api": artifactBlob}
	schemas := map[string]gitresource.Blob{"credential/v1": schemaBlob}
	artifactLocks, schemaLocks := tombstate.Locks(artifacts, schemas)
	policy := decree.Document{Version: 1, Generation: 1, ArtifactLocks: artifactLocks, SchemaLocks: schemaLocks, Rules: []decree.Rule{{Name: "allow", Seekers: decree.Selectors{Logins: []string{"alice@example.com"}, Tags: []string{"tag:ci"}}, Artifacts: []string{"production/**"}}}}
	decreeBytes, err := decree.Encode(policy)
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes, err := tombstate.EncodeDecreeSignature(manifestBytes, decreeBytes, manifest, signing)
	if err != nil {
		t.Fatal(err)
	}
	content := &gitresource.Content{Artifacts: artifacts, Schemas: schemas, Rotations: map[int]gitresource.RotationBlobs{}, Manifest: gitresource.Blob{Data: manifestBytes}, Decree: gitresource.Blob{Data: decreeBytes}, Signature: gitresource.Blob{Data: signatureBytes}}
	chamberPath, _ := chamber.Parse("production/api")
	resource := &lockedresource.Artifact{TombName: "default", Commit: strings.Repeat("a", 40), Chamber: chamberPath, Blob: artifactBlob, Content: content}
	configured := config.ProjectTomb{Lock: config.Lock{Commit: resource.Commit, ProclamationFingerprint: fingerprint, DecreeGeneration: 1, LockedAt: time.Now().UTC()}, Guardians: selections}
	return revealFixture{resource: resource, configured: configured, loader: loader, signing: signing}
}

func TestRevealLoginAndTagAuthorization(t *testing.T) {
	for name, identity := range map[string]seeker.Identity{"login": {Login: "alice@example.com"}, "tag-only": {Tags: []string{"tag:ci"}}} {
		t.Run(name, func(t *testing.T) {
			fixture := makeFixture(t, 1)
			defer fixture.signing.Destroy()
			seekers := &fakeSeekers{identity: identity}
			document, err := (Coordinator{Engine: artifact.Engine{}, Seekers: seekers, Guardians: fixture.loader}).Reveal(context.Background(), fixture.resource, fixture.configured)
			if err != nil {
				t.Fatal(err)
			}
			defer document.Destroy()
			if document.Secrets["token"] != "secret" {
				t.Fatal("wrong plaintext")
			}
			if seekers.calls != 1 {
				t.Fatal("live seeker was not queried exactly once")
			}
		})
	}
}

func TestRevealRejectsStaleProjectGenerationBeforeSeeker(t *testing.T) {
	fixture := makeFixture(t, 1)
	defer fixture.signing.Destroy()
	fixture.configured.Lock.DecreeGeneration = 0
	seekers := &fakeSeekers{identity: seeker.Identity{Login: "alice@example.com"}}
	if _, err := (Coordinator{Seekers: seekers, Guardians: fixture.loader}).Reveal(context.Background(), fixture.resource, fixture.configured); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("stale lock = %v", err)
	}
	if seekers.calls != 0 {
		t.Fatal("seeker queried before stale lock rejection")
	}
}

func TestRevealFailsBeforeGuardianWhenTailscaleUnavailable(t *testing.T) {
	fixture := makeFixture(t, 1)
	defer fixture.signing.Destroy()
	_, err := (Coordinator{Seekers: &fakeSeekers{err: fmt.Errorf("tailscaled unavailable")}, Guardians: fixture.loader}).Reveal(context.Background(), fixture.resource, fixture.configured)
	if err == nil || len(fixture.loader.calls) != 0 {
		t.Fatalf("missing Tailscale did not fail before guardian: %v, calls=%v", err, fixture.loader.calls)
	}
}

func TestRevealFailsBeforeGuardianForUnauthorizedSeeker(t *testing.T) {
	fixture := makeFixture(t, 1)
	defer fixture.signing.Destroy()
	_, err := (Coordinator{Seekers: &fakeSeekers{identity: seeker.Identity{Login: "mallory@example.com"}}, Guardians: fixture.loader}).Reveal(context.Background(), fixture.resource, fixture.configured)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unauthorized reveal = %v", err)
	}
	if len(fixture.loader.calls) != 0 {
		t.Fatalf("guardian loaded before authorization: %v", fixture.loader.calls)
	}
}

func TestRevealUsesConfiguredGuardianOrder(t *testing.T) {
	fixture := makeFixture(t, 1)
	defer fixture.signing.Destroy()
	otherName, _ := guardian.ParseName("first-but-ineligible")
	other, _ := guardian.GenerateRecord(otherName, time.Now().UTC())
	data, _ := other.MarshalJSON()
	other.Destroy()
	fixture.loader.records[string(otherName)] = data
	fixture.configured.Guardians = append([]config.GuardianSelection{{Name: otherName, Provider: guardian.AppleLoginKeychain}}, fixture.configured.Guardians...)
	document, err := (Coordinator{Seekers: &fakeSeekers{identity: seeker.Identity{Login: "alice@example.com"}}, Guardians: fixture.loader}).Reveal(context.Background(), fixture.resource, fixture.configured)
	if err != nil {
		t.Fatal(err)
	}
	document.Destroy()
	if len(fixture.loader.calls) != 2 || fixture.loader.calls[0] != string(otherName) {
		t.Fatalf("guardian order = %v", fixture.loader.calls)
	}
}

func TestRevealZeroAndNoIntersectingGuardians(t *testing.T) {
	zero := makeFixture(t, 0)
	defer zero.signing.Destroy()
	zero.configured.Guardians = []config.GuardianSelection{{Name: "absent", Provider: guardian.Environment}}
	if _, err := (Coordinator{Seekers: &fakeSeekers{identity: seeker.Identity{Login: "alice@example.com"}}, Guardians: zero.loader}).Reveal(context.Background(), zero.resource, zero.configured); err == nil || !strings.Contains(err.Error(), "zero guardian") {
		t.Fatalf("zero guardians = %v", err)
	}
	one := makeFixture(t, 1)
	defer one.signing.Destroy()
	otherName, _ := guardian.ParseName("other")
	other, _ := guardian.GenerateRecord(otherName, time.Now().UTC())
	data, _ := other.MarshalJSON()
	other.Destroy()
	one.loader.records[string(otherName)] = data
	one.configured.Guardians = []config.GuardianSelection{{Name: otherName, Provider: guardian.Environment}}
	if _, err := (Coordinator{Seekers: &fakeSeekers{identity: seeker.Identity{Login: "alice@example.com"}}, Guardians: one.loader}).Reveal(context.Background(), one.resource, one.configured); err == nil || !strings.Contains(err.Error(), "intersects") {
		t.Fatalf("non-intersection = %v", err)
	}
}
