package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marksisson/sphinx/internal/relic"
	"github.com/marksisson/sphinx/internal/secret"
	tombpkg "github.com/marksisson/sphinx/internal/tomb"
)

func TestValidateTombCandidate(t *testing.T) {
	root := t.TempDir()
	_, publicKey, err := secret.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	const passphrase = "correct horse battery staple"
	check, err := secret.NewRecoveryCheck(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := tombpkg.WriteConfiguration(root, tombpkg.Configuration{
		Format: 1, PublicKey: publicKey,
		Recovery: tombpkg.RecoveryConfiguration{Type: secret.RecoveryType, EncryptedCheck: check},
	}); err != nil {
		t.Fatal(err)
	}
	schemaDirectory := filepath.Join(root, ".sphinx", "schemas")
	if err := os.MkdirAll(schemaDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	definition := []byte("name: api-key\nversion: 1\nessence:\n  - name: value\n    type: string\n    required: true\n")
	if err := os.WriteFile(filepath.Join(schemaDirectory, "api-key.yaml"), definition, 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := relic.MarshalPlain(relic.Document{
		Format: relic.FormatVersion, Schema: "api-key/v1", Essence: map[string]any{"value": "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := secret.Encrypt(plaintext, publicKey, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if err := relic.WriteAtomic(root, "service/key", encrypted); err != nil {
		t.Fatal(err)
	}

	relics, schemas, err := validateTombCandidate(root)
	if err != nil {
		t.Fatal(err)
	}
	if relics != 1 || schemas != 1 {
		t.Fatalf("validated %d relics and %d schemas", relics, schemas)
	}
}

func TestValidateTombCandidateRejectsPublicKeyMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".sphinx", "schemas"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".sphinx", "schemas", "schema.yaml"), []byte("name: key\nversion: 1\nessence:\n  - name: value\n    type: string\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, firstPublicKey, _ := secret.GenerateKeyPair()
	_, secondPublicKey, _ := secret.GenerateKeyPair()
	check, _ := secret.NewRecoveryCheck("strong passphrase")
	if err := tombpkg.WriteConfiguration(root, tombpkg.Configuration{Format: 1, PublicKey: secondPublicKey, Recovery: tombpkg.RecoveryConfiguration{Type: secret.RecoveryType, EncryptedCheck: check}}); err != nil {
		t.Fatal(err)
	}
	plain, _ := relic.MarshalPlain(relic.Document{Format: 1, Schema: "key/v1", Essence: map[string]any{"value": "secret"}})
	encrypted, _ := secret.Encrypt(plain, firstPublicKey, "strong passphrase")
	if err := relic.WriteAtomic(root, "key", encrypted); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateTombCandidate(root); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("public key mismatch error = %v", err)
	}
}
