package proclamationrotation

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/decree"
	"github.com/marksisson/sphinx/internal/gitenv"
	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/hybridage"
	"github.com/marksisson/sphinx/internal/hybridsign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/tombstate"
	"github.com/marksisson/sphinx/internal/transaction"
	"github.com/marksisson/sphinx/internal/worktree"
)

type testKeys struct {
	public  proclamation.PublicBundle
	age     *age.HybridIdentity
	signing *hybridsign.PrivateBundle
}

func (k testKeys) Public() proclamation.PublicBundle          { return k.public }
func (k testKeys) AgeIdentity() *age.HybridIdentity           { return k.age }
func (k testKeys) SigningIdentity() *hybridsign.PrivateBundle { return k.signing }
func newKeys(t *testing.T, fill byte) testKeys {
	t.Helper()
	identity, err := hybridage.IdentityFromSeed(bytes.Repeat([]byte{fill}, 32))
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
	for i := range salt {
		salt[i] = fill
	}
	return testKeys{age: identity, signing: signing, public: proclamation.PublicBundle{KDF: proclamation.KDFSuite, Salt: salt.String(), AgeSuite: hybridage.Suite, AgeRecipient: hybridage.Recipient(identity), SignatureSuite: hybridsign.Suite, SigningPublic: proclamation.SigningPublic{Ed25519: ed, MLDSA65: ml}, Fingerprint: fingerprint}}
}

type rotationFixture struct {
	tree       *worktree.Worktree
	current    *gitresource.Content
	old, next  testKeys
	definition schema.Definition
	engine     artifact.Engine
	pre        map[string][]byte
}

func makeRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	git(t, root, "config", "user.email", "test@example.com")
	git(t, root, "config", "user.name", "Test")
	old, next := newKeys(t, 60), newKeys(t, 70)
	manifest := tombstate.Manifest{Version: 1, TombID: "123e4567-e89b-42d3-a456-426614174000", Proclamation: tombstate.Proclamation{KDF: old.public.KDF, Salt: old.public.Salt, AgeSuite: old.public.AgeSuite, AgeRecipient: old.public.AgeRecipient, SignatureSuite: old.public.SignatureSuite, PublicKey: tombstate.PublicKey{Ed25519: old.public.SigningPublic.Ed25519, MLDSA65: old.public.SigningPublic.MLDSA65}, Fingerprint: old.public.Fingerprint}}
	manifestBytes, _ := tombstate.EncodeManifest(manifest)
	definition := schema.Definition{Version: 1, Name: "credential", Secrets: []schema.Field{{Name: "token", Type: "string", Required: true, Prompt: "Token"}}}
	schemaBytes := []byte("version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n")
	engine := artifact.Engine{Random: bytes.NewReader(bytes.Repeat([]byte{9}, 2048)), Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	encrypted, err := engine.Create(artifact.Document{Format: 1, Schema: "credential/v1", Inscriptions: map[string]any{}, Secrets: map[string]any{"token": "value"}}, definition, old.public.AgeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	guardName, _ := guardian.ParseName("fixture-guardian")
	record, _ := guardian.GenerateRecord(guardName, time.Now().UTC())
	encrypted, err = engine.AddRecipient(encrypted, old.age, definition, record.Recipient())
	record.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	artifactBlob := gitresource.Blob{Path: "production/api/artifact.yaml", Data: encrypted}
	schemaBlob := gitresource.Blob{Path: ".tomb/schemas/credential/v1.yaml", Data: schemaBytes}
	artifacts := map[string]gitresource.Blob{"production/api": artifactBlob}
	schemas := map[string]gitresource.Blob{"credential/v1": schemaBlob}
	al, sl := tombstate.Locks(artifacts, schemas)
	policy := decree.Document{Version: 1, Generation: 1, ArtifactLocks: al, SchemaLocks: sl, Rules: []decree.Rule{}}
	decreeBytes, _ := decree.Encode(policy)
	signature, _ := tombstate.EncodeDecreeSignature(manifestBytes, decreeBytes, manifest, old.signing)
	pre := map[string][]byte{".tomb/tomb.yaml": manifestBytes, ".tomb/decree.yaml": decreeBytes, ".tomb/decree.yaml.sig": signature, ".tomb/rotations/.keep": {}, ".tomb/schemas/credential/v1.yaml": schemaBytes, "production/api/artifact.yaml": encrypted}
	for path, data := range pre {
		filename := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filename, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "initial")
	tree, err := worktree.Open(context.Background(), "path:"+root, root, "")
	if err != nil {
		t.Fatal(err)
	}
	current := &gitresource.Content{Artifacts: artifacts, Schemas: schemas, Rotations: map[int]gitresource.RotationBlobs{}, Manifest: gitresource.Blob{Path: ".tomb/tomb.yaml", Data: manifestBytes}, Decree: gitresource.Blob{Path: ".tomb/decree.yaml", Data: decreeBytes}, Signature: gitresource.Blob{Path: ".tomb/decree.yaml.sig", Data: signature}}
	return rotationFixture{tree: tree, current: current, old: old, next: next, definition: definition, engine: engine, pre: pre}
}

func TestCompleteProclamationRotation(t *testing.T) {
	fixture := makeRotationFixture(t)
	defer fixture.old.signing.Destroy()
	defer fixture.next.signing.Destroy()
	if err := Rotate(context.Background(), fixture.tree, fixture.engine, fixture.current, fixture.old, fixture.next, transaction.Options{}); err != nil {
		t.Fatal(err)
	}
	manifestBytes, _ := os.ReadFile(filepath.Join(fixture.tree.Root, ".tomb/tomb.yaml"))
	manifest, err := tombstate.DecodeManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Proclamation.Fingerprint != fixture.next.public.Fingerprint {
		t.Fatal("manifest did not rotate")
	}
	decreeBytes, _ := os.ReadFile(filepath.Join(fixture.tree.Root, ".tomb/decree.yaml"))
	policy, _ := decree.Decode(decreeBytes)
	if policy.Generation != 2 {
		t.Fatalf("generation = %d", policy.Generation)
	}
	encrypted, _ := os.ReadFile(filepath.Join(fixture.tree.Root, "production/api/artifact.yaml"))
	if _, _, err := fixture.engine.DecryptWithIdentities(encrypted, fixture.next.public.AgeRecipient, []*age.HybridIdentity{fixture.next.age}, fixture.definition); err != nil {
		t.Fatalf("new proclamation cannot decrypt: %v", err)
	}
	if _, _, err := fixture.engine.DecryptWithIdentities(encrypted, fixture.next.public.AgeRecipient, []*age.HybridIdentity{fixture.old.age}, fixture.definition); err == nil {
		t.Fatal("old proclamation decrypted rotated artifact")
	}
	if _, err := os.Stat(filepath.Join(fixture.tree.Root, ".tomb/rotations/00000001.to.sig")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(fixture.tree.Root, ".tomb/tomb.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("manifest mode = %v", info.Mode().Perm())
	}
}

func TestRotationRollbackAtEveryInstallStep(t *testing.T) {
	for failAt := 1; failAt <= 7; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			fixture := makeRotationFixture(t)
			defer fixture.old.signing.Destroy()
			defer fixture.next.signing.Destroy()
			err := Rotate(context.Background(), fixture.tree, fixture.engine, fixture.current, fixture.old, fixture.next, transaction.Options{Hook: func(phase string, installed int) error {
				if phase == "installed" && installed == failAt {
					return fmt.Errorf("injected")
				}
				return nil
			}})
			if err == nil {
				t.Fatal("injected failure accepted")
			}
			for path, expected := range fixture.pre {
				actual, readErr := os.ReadFile(filepath.Join(fixture.tree.Root, filepath.FromSlash(path)))
				if readErr != nil || !bytes.Equal(actual, expected) {
					t.Fatalf("pre-image %q not restored", path)
				}
			}
			if _, err := os.Stat(filepath.Join(fixture.tree.Root, ".tomb/rotations/00000001.yaml")); !os.IsNotExist(err) {
				t.Fatal("new transition survived rollback")
			}
		})
	}
}

func git(t *testing.T, directory string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Env = gitenv.Environment()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, strings.TrimSpace(string(output)))
	}
}
