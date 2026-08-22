package tombstate

import (
	"strings"
	"testing"
)

func TestSignDraftReplacesManagedGenerationAndLocks(t *testing.T) {
	bundle := newBundle(t, 80)
	defer bundle.signing.Destroy()
	current := signedContent(t, bundle, 6, "operators")
	draft := []byte("version: 1\ngeneration: 999\nartifact_locks: []\nschema_locks: []\nrules:\n  - name: operators\n    seekers:\n      logins: [alice@example.com]\n      tags: []\n    artifacts: [production/**]\n")
	decreeBytes, signature, err := SignDraft(current.Manifest.Data, draft, 6, current.Artifacts, current.Schemas, bundle.signing)
	if err != nil {
		t.Fatal(err)
	}
	candidate := *current
	candidate.Decree.Data = decreeBytes
	candidate.Signature.Data = signature
	verified, err := Verify(&candidate, bundle.manifest.Proclamation.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Decree.Generation != 7 || len(verified.Decree.ArtifactLocks) != 1 || len(verified.Decree.SchemaLocks) != 1 {
		t.Fatalf("signed draft = %#v", verified.Decree)
	}
	if strings.Contains(string(decreeBytes), "999") {
		t.Fatal("editor-authored generation survived")
	}
}

func TestSignDraftRejectsWrongProclamationAndPolicyFields(t *testing.T) {
	bundle := newBundle(t, 90)
	defer bundle.signing.Destroy()
	wrong := newBundle(t, 91)
	defer wrong.signing.Destroy()
	current := signedContent(t, bundle, 1, "")
	draft := []byte("version: 1\ngeneration: 1\nartifact_locks: []\nschema_locks: []\nrules: []\n")
	if _, _, err := SignDraft(current.Manifest.Data, draft, 1, current.Artifacts, current.Schemas, wrong.signing); err == nil {
		t.Fatal("wrong proclamation signed draft")
	}
	bad := []byte("version: 1\ngeneration: 1\nartifact_locks: []\nschema_locks: []\nrules: []\ndeny: true\n")
	if _, _, err := SignDraft(current.Manifest.Data, bad, 1, current.Artifacts, current.Schemas, bundle.signing); err == nil {
		t.Fatal("deny field accepted")
	}
}
