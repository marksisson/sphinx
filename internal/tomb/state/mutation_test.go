package state

import (
	"io/fs"
	"math"
	"testing"

	"github.com/marksisson/sphinx/internal/artifact/mutation"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	managedpath "github.com/marksisson/sphinx/internal/tomb/path"
)

type mutationView struct {
	files   map[string][]byte
	entries []managedpath.Entry
}

func (v mutationView) Read(path string) ([]byte, fs.FileMode, bool, error) {
	data, ok := v.files[path]
	return append([]byte(nil), data...), 0o600, ok, nil
}
func (v mutationView) ManagedPaths() ([]managedpath.Entry, error) {
	return append([]managedpath.Entry(nil), v.entries...), nil
}

func TestMutationBuilderIncrementsAndRegeneratesLocks(t *testing.T) {
	bundle := newBundle(t, 40)
	defer bundle.signing.Destroy()
	current := signedContent(t, bundle, 9, "operators")
	view := mutationView{files: map[string][]byte{".tomb/tomb.yaml": current.Manifest.Data, mutation.DecreePath: current.Decree.Data, "production/api/artifact.yaml": current.Artifacts["production/api"].Data, ".tomb/schemas/credential/v1.yaml": current.Schemas["credential/v1"].Data}, entries: []managedpath.Entry{{Path: ".tomb/schemas/credential/v1.yaml", Key: "credential/v1", Kind: managedpath.Schema}, {Path: "production/api/artifact.yaml", Key: "production/api", Kind: managedpath.Artifact}}}
	builder, err := NewMutationBuilder(current, bundle.manifest.Proclamation.Fingerprint, bundle.signing)
	if err != nil {
		t.Fatal(err)
	}
	state, err := builder.Build(view)
	if err != nil {
		t.Fatal(err)
	}
	content := &gitresource.Content{Artifacts: map[string]gitresource.Blob{"production/api": {Data: view.files["production/api/artifact.yaml"]}}, Schemas: map[string]gitresource.Blob{"credential/v1": {Data: view.files[".tomb/schemas/credential/v1.yaml"]}}, Rotations: map[int]gitresource.RotationBlobs{}, Manifest: current.Manifest, Decree: gitresource.Blob{Data: state.Decree}, Signature: gitresource.Blob{Data: state.Signature}}
	verified, err := Verify(content, bundle.manifest.Proclamation.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Decree.Generation != 10 {
		t.Fatalf("generation = %d", verified.Decree.Generation)
	}
	if verified.Decree.ArtifactLocks[0].SHA256 != content.Artifacts["production/api"].SHA256Hex() {
		t.Fatal("artifact lock was not regenerated")
	}
	dependencies, err := builder.Dependencies(view)
	if err != nil {
		t.Fatal(err)
	}
	if len(dependencies) != 3 || dependencies[0] != ".tomb/tomb.yaml" {
		t.Fatalf("dependencies = %v", dependencies)
	}
}

func TestMutationBuilderRejectsUnauthenticatedCurrentPolicy(t *testing.T) {
	bundle := newBundle(t, 45)
	defer bundle.signing.Destroy()
	content := signedContent(t, bundle, 2, "operators")
	content.Decree.Data = append([]byte(nil), content.Decree.Data...)
	content.Decree.Data[20] ^= 1
	if _, err := NewMutationBuilder(content, bundle.manifest.Proclamation.Fingerprint, bundle.signing); err == nil {
		t.Fatal("tampered current policy authorized a mutation")
	}
}

func TestMutationBuilderRejectsGenerationOverflow(t *testing.T) {
	bundle := newBundle(t, 50)
	defer bundle.signing.Destroy()
	content := signedContent(t, bundle, math.MaxUint64, "")
	builder, err := NewMutationBuilder(content, bundle.manifest.Proclamation.Fingerprint, bundle.signing)
	if err != nil {
		t.Fatal(err)
	}
	view := mutationView{files: map[string][]byte{".tomb/tomb.yaml": content.Manifest.Data, mutation.DecreePath: content.Decree.Data}, entries: []managedpath.Entry{{Path: ".tomb/schemas/credential/v1.yaml", Key: "credential/v1", Kind: managedpath.Schema}, {Path: "production/api/artifact.yaml", Key: "production/api", Kind: managedpath.Artifact}}}
	view.files[".tomb/schemas/credential/v1.yaml"] = content.Schemas["credential/v1"].Data
	view.files["production/api/artifact.yaml"] = content.Artifacts["production/api"].Data
	if _, err := builder.Build(view); err == nil {
		t.Fatal("generation overflow accepted")
	}
}
