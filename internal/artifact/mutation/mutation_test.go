package mutation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/artifact"
	gitenv "github.com/marksisson/sphinx/internal/git/env"
	"github.com/marksisson/sphinx/internal/git/worktree"
	hybridage "github.com/marksisson/sphinx/internal/hybrid/age"
	hybridsign "github.com/marksisson/sphinx/internal/hybrid/sign"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/tomb/transaction"
)

const mutationTombID = "123e4567-e89b-42d3-a456-426614174000"

type signingBuilder struct {
	path    string
	signing *hybridsign.PrivateBundle
	calls   int
}

func (b *signingBuilder) Build(view View) (SignedState, error) {
	b.calls++
	data, _, exists, err := view.Read(b.path)
	if err != nil {
		return SignedState{}, err
	}
	state := "deleted\n"
	if exists {
		sum := sha256.Sum256(data)
		state = fmt.Sprintf("%s %x\n", b.path, sum)
	}
	digest := sha256.Sum256([]byte("manifest"))
	signature, err := b.signing.Sign(hybridsign.DecreePurpose, mutationTombID, digest[:], []byte(state))
	if err != nil {
		return SignedState{}, err
	}
	ed, ml := signature.Encoded()
	return SignedState{Decree: []byte(state), Signature: []byte(ed + "\n" + ml + "\n")}, nil
}

func TestCreateDeleteAndSignedLockCoupling(t *testing.T) {
	tree := mutationWorktree(t)
	signing := mutationSigning(t)
	defer signing.Destroy()
	builder := &signingBuilder{path: "prod/api/artifact.yaml", signing: signing}
	validate := signedValidator(builder.path, signing.Public())
	artifact := []byte("encrypted artifact bytes\n")
	if err := Apply(context.Background(), tree, map[string]transaction.PostImage{builder.path: {Data: artifact, Mode: 0o600}}, builder, validate, transaction.Options{}); err != nil {
		t.Fatal(err)
	}
	if builder.calls != 1 {
		t.Fatalf("builder calls = %d", builder.calls)
	}
	data, err := os.ReadFile(filepath.Join(tree.Root, builder.path))
	if err != nil || string(data) != string(artifact) {
		t.Fatalf("created artifact = %q, %v", data, err)
	}
	mutationGit(t, tree.Root, "add", builder.path, DecreePath, SignaturePath)
	mutationGit(t, tree.Root, "commit", "-m", "create")
	if err := Apply(context.Background(), tree, map[string]transaction.PostImage{builder.path: {Delete: true}}, builder, validate, transaction.Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(tree.Root, builder.path)); !os.IsNotExist(err) {
		t.Fatalf("deleted artifact still exists: %v", err)
	}
	decree, _ := os.ReadFile(filepath.Join(tree.Root, DecreePath))
	if string(decree) != "deleted\n" {
		t.Fatalf("delete lock state = %q", decree)
	}
}

func TestMutationRollbackRestoresArtifactDecreeAndSignature(t *testing.T) {
	tree := mutationWorktree(t)
	path := "prod/api/artifact.yaml"
	old := []byte("old encrypted artifact\n")
	if err := os.MkdirAll(filepath.Join(tree.Root, "prod/api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree.Root, path), old, 0o600); err != nil {
		t.Fatal(err)
	}
	mutationGit(t, tree.Root, "add", path)
	mutationGit(t, tree.Root, "commit", "-m", "artifact")
	signing := mutationSigning(t)
	defer signing.Destroy()
	builder := &signingBuilder{path: path, signing: signing}
	validate := signedValidator(path, signing.Public())
	oldDecree, _ := os.ReadFile(filepath.Join(tree.Root, DecreePath))
	oldSignature, _ := os.ReadFile(filepath.Join(tree.Root, SignaturePath))
	err := Apply(context.Background(), tree, map[string]transaction.PostImage{path: {Data: []byte("new encrypted artifact\n"), Mode: 0o600}}, builder, validate, transaction.Options{Hook: func(phase string, installed int) error {
		if phase == "installed" && installed == 3 {
			return fmt.Errorf("injected")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("injected transaction failure succeeded")
	}
	assertMutationFile(t, tree.Root, path, old)
	assertMutationFile(t, tree.Root, DecreePath, oldDecree)
	assertMutationFile(t, tree.Root, SignaturePath, oldSignature)
}

func TestMutationRejectsArtifactOnlyOrIncompleteSignedState(t *testing.T) {
	tree := mutationWorktree(t)
	path := "prod/api/artifact.yaml"
	signing := mutationSigning(t)
	defer signing.Destroy()
	bad := builderFunc(func(View) (SignedState, error) { return SignedState{Decree: []byte("unsigned\n")}, nil })
	err := Apply(context.Background(), tree, map[string]transaction.PostImage{path: {Data: []byte("ciphertext\n"), Mode: 0o600}}, bad, func(View) error { return nil }, transaction.Options{})
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete signed state = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tree.Root, path)); !os.IsNotExist(err) {
		t.Fatal("artifact-only write reached worktree")
	}
	wrongDigest := builderFunc(func(View) (SignedState, error) {
		decree := []byte(path + " " + strings.Repeat("0", 64) + "\n")
		digest := sha256.Sum256([]byte("manifest"))
		signature, err := signing.Sign(hybridsign.DecreePurpose, mutationTombID, digest[:], decree)
		if err != nil {
			return SignedState{}, err
		}
		ed, ml := signature.Encoded()
		return SignedState{Decree: decree, Signature: []byte(ed + "\n" + ml + "\n")}, nil
	})
	err = Apply(context.Background(), tree, map[string]transaction.PostImage{path: {Data: []byte("ciphertext\n"), Mode: 0o600}}, wrongDigest, signedValidator(path, signing.Public()), transaction.Options{})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("wrong artifact digest = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tree.Root, path)); !os.IsNotExist(err) {
		t.Fatal("digest-mismatched artifact reached worktree")
	}
	good := &signingBuilder{path: path, signing: signing}
	err = Apply(context.Background(), tree, map[string]transaction.PostImage{DecreePath: {Data: []byte("caller decree"), Mode: 0o600}}, good, func(View) error { return nil }, transaction.Options{})
	if err == nil {
		t.Fatal("caller-supplied decree accepted")
	}
	err = Apply(context.Background(), tree, map[string]transaction.PostImage{"safe/.git/artifact.yaml": {Data: []byte("ciphertext"), Mode: 0o600}}, good, func(View) error { return nil }, transaction.Options{})
	if err == nil {
		t.Fatal("reserved .git chamber mutation accepted")
	}
}

func TestScopedGuardianRollbackRestoresEveryArtifactAndSignedState(t *testing.T) {
	tree := mutationWorktree(t)
	definition := schema.Definition{Version: 1, Name: "service", Secrets: []schema.Field{{Name: "token", Type: "string", Required: true, Prompt: "Token"}}}
	proclamation, _ := hybridage.Generate()
	guardian, _ := hybridage.Generate()
	createEngine := artifact.Engine{Random: bytes.NewReader(bytes.Repeat([]byte{1}, 64)), Now: func() time.Time { return time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC) }}
	paths := []string{"prod/a/artifact.yaml", "prod/b/artifact.yaml"}
	originals := make(map[string][]byte, len(paths))
	for index, path := range paths {
		document := artifact.Document{Format: 1, Schema: "service/v1", Inscriptions: map[string]any{}, Secrets: map[string]any{"token": fmt.Sprintf("secret-%d", index)}}
		encrypted, err := createEngine.Create(document, definition, proclamation.Recipient().String())
		if err != nil {
			t.Fatal(err)
		}
		originals[path] = encrypted
		filename := filepath.Join(tree.Root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, encrypted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mutationGit(t, tree.Root, "add", ".")
	mutationGit(t, tree.Root, "commit", "-m", "two artifacts")
	signing := mutationSigning(t)
	defer signing.Destroy()
	builder := &multiSigningBuilder{paths: paths, signing: signing}
	selected := []ScopedArtifact{{Path: paths[0], Encrypted: originals[paths[0]], Mode: 0o600, Definition: definition}, {Path: paths[1], Encrypted: originals[paths[1]], Mode: 0o600, Definition: definition}}
	engine := artifact.Engine{Random: bytes.NewReader(append(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)...)), Now: createEngine.Now}
	err := AddGuardian(context.Background(), tree, engine, proclamation, guardian.Recipient().String(), selected, builder, multiSignedValidator(paths, signing.Public()), transaction.Options{Hook: func(phase string, installed int) error {
		if phase == "installed" && installed == 3 {
			return fmt.Errorf("injected")
		}
		return nil
	}})
	if err == nil {
		t.Fatal("injected scoped guardian transaction succeeded")
	}
	for _, path := range paths {
		assertMutationFile(t, tree.Root, path, originals[path])
	}
}

type multiSigningBuilder struct {
	paths   []string
	signing *hybridsign.PrivateBundle
}

func (b *multiSigningBuilder) Build(view View) (SignedState, error) {
	var decree strings.Builder
	for _, path := range b.paths {
		data, _, exists, err := view.Read(path)
		if err != nil || !exists {
			return SignedState{}, fmt.Errorf("missing %s", path)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&decree, "%s %x\n", path, sum)
	}
	digest := sha256.Sum256([]byte("manifest"))
	signature, err := b.signing.Sign(hybridsign.DecreePurpose, mutationTombID, digest[:], []byte(decree.String()))
	if err != nil {
		return SignedState{}, err
	}
	ed, ml := signature.Encoded()
	return SignedState{Decree: []byte(decree.String()), Signature: []byte(ed + "\n" + ml + "\n")}, nil
}
func multiSignedValidator(paths []string, public hybridsign.PublicBundle) Validator {
	return func(view View) error {
		decree, _, exists, err := view.Read(DecreePath)
		if err != nil || !exists {
			return fmt.Errorf("missing decree")
		}
		signatureBytes, _, exists, err := view.Read(SignaturePath)
		if err != nil || !exists {
			return fmt.Errorf("missing signature")
		}
		parts := strings.Split(strings.TrimSuffix(string(signatureBytes), "\n"), "\n")
		if len(parts) != 2 {
			return fmt.Errorf("invalid signature")
		}
		signature, err := hybridsign.ParseSignature(parts[0], parts[1])
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte("manifest"))
		if err := public.Verify(hybridsign.DecreePurpose, mutationTombID, digest[:], decree, signature); err != nil {
			return err
		}
		var want strings.Builder
		for _, path := range paths {
			data, _, exists, err := view.Read(path)
			if err != nil || !exists {
				return fmt.Errorf("missing artifact")
			}
			sum := sha256.Sum256(data)
			fmt.Fprintf(&want, "%s %x\n", path, sum)
		}
		if string(decree) != want.String() {
			return fmt.Errorf("exhaustive digest mismatch")
		}
		return nil
	}
}

type builderFunc func(View) (SignedState, error)

func (f builderFunc) Build(v View) (SignedState, error) { return f(v) }

func signedValidator(path string, public hybridsign.PublicBundle) Validator {
	return func(view View) error {
		decree, _, exists, err := view.Read(DecreePath)
		if err != nil || !exists {
			return fmt.Errorf("missing decree")
		}
		sigBytes, _, exists, err := view.Read(SignaturePath)
		if err != nil || !exists {
			return fmt.Errorf("missing signature")
		}
		parts := strings.Split(strings.TrimSuffix(string(sigBytes), "\n"), "\n")
		if len(parts) != 2 {
			return fmt.Errorf("invalid signature")
		}
		signature, err := hybridsign.ParseSignature(parts[0], parts[1])
		if err != nil {
			return err
		}
		digest := sha256.Sum256([]byte("manifest"))
		if err := public.Verify(hybridsign.DecreePurpose, mutationTombID, digest[:], decree, signature); err != nil {
			return err
		}
		data, _, artifactExists, err := view.Read(path)
		if err != nil {
			return err
		}
		if string(decree) == "deleted\n" {
			if artifactExists {
				return fmt.Errorf("delete lock retains artifact")
			}
			return nil
		}
		if !artifactExists {
			return fmt.Errorf("lock has no artifact")
		}
		sum := sha256.Sum256(data)
		want := fmt.Sprintf("%s %x\n", path, sum)
		if string(decree) != want {
			return fmt.Errorf("artifact digest mismatch")
		}
		return nil
	}
}

func mutationSigning(t *testing.T) *hybridsign.PrivateBundle {
	t.Helper()
	ed := make([]byte, 32)
	ml := make([]byte, 32)
	for i := range ed {
		ed[i] = byte(i + 1)
		ml[i] = byte(255 - i)
	}
	value, err := hybridsign.NewPrivate(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func mutationWorktree(t *testing.T) *worktree.Worktree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mutationGit(t, root, "init")
	mutationGit(t, root, "config", "user.email", "test@example.invalid")
	mutationGit(t, root, "config", "user.name", "Test")
	for path, data := range map[string][]byte{DecreePath: []byte("old decree\n"), SignaturePath: []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + "\n" + base64.RawURLEncoding.EncodeToString(make([]byte, 3309)) + "\n"), ".tomb/schemas/service/v1.yaml": []byte("version: 1\n")} {
		filename := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "prod/api"), 0o700); err != nil {
		t.Fatal(err)
	}
	mutationGit(t, root, "add", ".")
	mutationGit(t, root, "commit", "-m", "initial")
	tree, err := worktree.Open(context.Background(), "path:"+root, root, "")
	if err != nil {
		t.Fatal(err)
	}
	return tree
}
func mutationGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = gitenv.Environment()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s", args, out)
	}
}
func assertMutationFile(t *testing.T, root, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(root, path))
	if err != nil || string(got) != string(want) {
		t.Fatalf("%s = %q, %v", path, got, err)
	}
}
