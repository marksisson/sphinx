package state

import (
	"bytes"
	"testing"

	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/proclamation"
)

func TestInitializeCreatesDefaultDenySignedState(t *testing.T) {
	credential := proclamation.NewCredential([]byte("abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion"))
	defer credential.Destroy()
	derived, err := proclamation.Derive(credential, proclamation.Salt{})
	if err != nil {
		t.Fatal(err)
	}
	defer derived.Destroy()
	schemaBytes := []byte("version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n")
	schemas := map[string]gitresource.Blob{"credential/v1": {Path: ".tomb/schemas/credential/v1.yaml", Data: schemaBytes}}
	source := bytes.NewReader(bytes.Repeat([]byte{0x42}, 16))
	state, err := Initialize(schemas, derived, source)
	if err != nil {
		t.Fatal(err)
	}
	content := &gitresource.Content{Artifacts: map[string]gitresource.Blob{}, Schemas: schemas, Rotations: map[int]gitresource.RotationBlobs{}, Manifest: gitresource.Blob{Data: state.Manifest}, Decree: gitresource.Blob{Data: state.Decree}, Signature: gitresource.Blob{Data: state.Signature}}
	verified, err := VerifyCurrent(content)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Decree.Generation != 1 || len(verified.Decree.Rules) != 0 || len(verified.Decree.ArtifactLocks) != 0 || len(verified.Decree.SchemaLocks) != 1 {
		t.Fatalf("initial decree=%#v", verified.Decree)
	}
	if state.TombID != "42424242-4242-4242-8242-424242424242" {
		t.Fatalf("tomb ID=%s", state.TombID)
	}
}
func TestInitializeRejectsMissingSchema(t *testing.T) {
	if _, err := Initialize(map[string]gitresource.Blob{}, nil, bytes.NewReader(nil)); err == nil {
		t.Fatal("missing schema accepted")
	}
}
