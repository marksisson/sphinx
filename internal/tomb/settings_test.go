package tomb

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadSettings(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "sphinx.yaml")
	data := []byte(`version: 1
default_tomb: production
tombs:
  production:
    locator: github:example/secrets/pull/42/head?dir=secrets
    lock: locks/production.yaml
    decree: decree.yaml
    guardian:
      keychain_service: example.service
      keychain_account: example-account
`)
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := LoadSettings(filename, "")
	if err != nil {
		t.Fatal(err)
	}
	if settings.Name != "production" || settings.Ref != "pull/42/head" || settings.Path != "secrets" {
		t.Fatalf("settings = %#v", settings)
	}
	if settings.Lock != filepath.Join(directory, "locks", "production.yaml") {
		t.Fatalf("lock = %q", settings.Lock)
	}
	if settings.Guardian.KeychainService != "example.service" {
		t.Fatalf("guardian = %#v", settings.Guardian)
	}
}

func TestLoadSettingsRejectsSelectorsOutsideLocator(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "sphinx.yaml")
	data := []byte(`version: 1
tombs:
  production:
    locator: github:example/secrets
    ref: main
    path: secrets
`)
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(filename, "production"); err == nil {
		t.Fatal("ref and path fields outside the tomb locator were accepted")
	}
}

func TestLockRoundTripAndMatch(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "production.lock.yaml")
	locator, err := ParseLocator("github:example/secrets/main?dir=secrets")
	if err != nil {
		t.Fatal(err)
	}
	settings := &RuntimeSettings{Name: "production", Locator: locator, Ref: "main", Path: "secrets"}
	want := Lock{
		Version: 1, Tomb: "production", Locator: locator.String(),
		Revision: "a3a3dda3bacf61e8a39258a0ed9c924eeca8e293", UpdatedAt: time.Now().UTC(),
	}
	if err := WriteLock(filename, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLock(filename)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != want.Revision {
		t.Fatalf("lock = %#v", got)
	}
	if err := got.Matches(settings); err != nil {
		t.Fatal(err)
	}
}
