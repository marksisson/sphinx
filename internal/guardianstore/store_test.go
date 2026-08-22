package guardianstore

import (
	"encoding/base64"
	"errors"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/keychain"
)

type memoryApple struct{ items map[string]KeychainItem }

func (m *memoryApple) Add(_, account, _ string, data []byte, synchronized bool) error {
	key := account + providerSuffix(synchronized)
	if _, exists := m.items[key]; exists {
		return keychain.ErrAlreadyExists
	}
	m.items[key] = KeychainItem{Account: account, Data: append([]byte(nil), data...), Synchronizable: synchronized}
	return nil
}
func (m *memoryApple) Get(_, account string, synchronized bool) ([]byte, error) {
	item, exists := m.items[account+providerSuffix(synchronized)]
	if !exists {
		return nil, keychain.ErrNotFound
	}
	return append([]byte(nil), item.Data...), nil
}
func (m *memoryApple) List(_ string) ([]KeychainItem, error) {
	out := make([]KeychainItem, 0, len(m.items))
	for _, item := range m.items {
		item.Data = append([]byte(nil), item.Data...)
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account < out[j].Account })
	return out, nil
}
func (m *memoryApple) Delete(_, account string, synchronized bool) error {
	key := account + providerSuffix(synchronized)
	if _, exists := m.items[key]; !exists {
		return keychain.ErrNotFound
	}
	delete(m.items, key)
	return nil
}
func providerSuffix(synchronized bool) string {
	if synchronized {
		return ":sync"
	}
	return ":local"
}

func TestAppleProvidersAreDistinctAndCreateDoesNotOverwrite(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("initial writable provider target is macOS")
	}
	backend := &memoryApple{items: make(map[string]KeychainItem)}
	store := Store{Apple: backend, Now: func() time.Time { return time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC) }}
	name, _ := guardian.ParseName("same")
	icloud, err := store.Create(name, guardian.AppleICloudKeychain)
	if err != nil {
		t.Fatal(err)
	}
	defer icloud.Destroy()
	login, err := store.Create(name, guardian.AppleLoginKeychain)
	if err != nil {
		t.Fatal(err)
	}
	defer login.Destroy()
	if icloud.Recipient() == login.Recipient() {
		t.Fatal("independent provider records reused an identity")
	}
	if _, err := store.Create(name, guardian.AppleICloudKeychain); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate create = %v", err)
	}
	listed, err := store.List(guardian.AppleICloudKeychain)
	if err != nil || len(listed) != 1 {
		t.Fatalf("List = %d, %v", len(listed), err)
	}
	destroyRecords(listed)
	if err := store.Delete(name, guardian.AppleICloudKeychain); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(name, guardian.AppleICloudKeychain); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted Get = %v", err)
	}
	if _, err := store.Get(name, guardian.AppleLoginKeychain); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentProviderIsFixedReadOnlyAndVerifiesName(t *testing.T) {
	name, _ := guardian.ParseName("ci")
	record, err := guardian.GenerateRecord(name, time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := record.MarshalJSON()
	record.Destroy()
	value := base64.RawURLEncoding.EncodeToString(encoded)
	clear(encoded)
	lookedUp := ""
	store := Store{LookupEnv: func(name string) (string, bool) { lookedUp = name; return value, true }}
	loaded, err := store.Get(name, guardian.Environment)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()
	if lookedUp != EnvironmentVariable {
		t.Fatalf("looked up %q", lookedUp)
	}
	other, _ := guardian.ParseName("other")
	if _, err := store.Get(other, guardian.Environment); err == nil {
		t.Fatal("environment name mismatch accepted")
	}
	if _, err := store.Create(name, guardian.Environment); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Create = %v", err)
	}
	if err := store.Delete(name, guardian.Environment); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Delete = %v", err)
	}
}

func TestProductionEnvironmentValueIsCapturedRemovedAndSingleUse(t *testing.T) {
	t.Setenv(EnvironmentVariable, "sensitive-record")
	store := New()
	if _, remains := os.LookupEnv(EnvironmentVariable); remains {
		t.Fatal("guardian identity remains in the process environment after store construction")
	}
	value, ok := store.environmentValue()
	if !ok || value != "sensitive-record" {
		t.Fatalf("environment value = %q, %v", value, ok)
	}
	if second, ok := store.environmentValue(); ok || second != "" {
		t.Fatalf("environment value was reusable: %q, %v", second, ok)
	}
}

func TestEnvironmentRejectsAlternateEncodingAndMissingValue(t *testing.T) {
	name, _ := guardian.ParseName("ci")
	store := Store{LookupEnv: func(string) (string, bool) { return "YWJj=", true }}
	if _, err := store.Get(name, guardian.Environment); err == nil {
		t.Fatal("padded environment encoding accepted")
	}
	store.LookupEnv = func(string) (string, bool) { return "", false }
	if _, err := store.Get(name, guardian.Environment); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing value = %v", err)
	}
}
