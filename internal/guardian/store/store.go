// Package store provides provider-authoritative guardian records. It
// never creates a filesystem registry and never exposes record export/import.
package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/guardian/keychain"
)

const (
	Service             = "dev.marksisson.sphinx.guardians"
	EnvironmentVariable = "SPHINX_GUARDIAN"
)

var (
	ErrNotFound      = errors.New("guardian not found")
	ErrAlreadyExists = errors.New("guardian already exists")
	ErrReadOnly      = errors.New("guardian provider is read-only")
	ErrUnsupported   = errors.New("guardian provider operation is unsupported")
)

type AppleBackend interface {
	Add(service, account, label string, data []byte, synchronizable bool) error
	Get(service, account string, synchronizable bool) ([]byte, error)
	List(service string) ([]KeychainItem, error)
	Delete(service, account string, synchronizable bool) error
}

type KeychainItem struct {
	Account        string
	Data           []byte
	Synchronizable bool
}

type Store struct {
	Apple     AppleBackend
	LookupEnv func(string) (string, bool)
	Now       func() time.Time
}

func New() Store {
	value, present := os.LookupEnv(EnvironmentVariable)
	if present {
		// Capture before command parsing, then remove the private record from the
		// live process environment. The closure releases its copy after one use.
		_ = os.Unsetenv(EnvironmentVariable)
	}
	var lock sync.Mutex
	lookup := func(name string) (string, bool) {
		lock.Lock()
		defer lock.Unlock()
		if name != EnvironmentVariable || !present {
			return "", false
		}
		result := value
		value, present = "", false
		return result, true
	}
	return Store{Apple: nativeAppleBackend{}, LookupEnv: lookup, Now: time.Now}
}

func (s Store) Create(name guardian.Name, provider guardian.Provider) (*guardian.Record, error) {
	if _, err := guardian.ParseName(string(name)); err != nil {
		return nil, err
	}
	if provider == guardian.Environment {
		return nil, ErrReadOnly
	}
	synchronized, err := appleSynchronization(provider)
	if err != nil {
		return nil, err
	}
	if s.Apple == nil || runtime.GOOS != "darwin" {
		return nil, ErrUnsupported
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	record, err := guardian.GenerateRecord(name, now.UTC())
	if err != nil {
		return nil, err
	}
	encoded, err := record.MarshalJSON()
	if err != nil {
		record.Destroy()
		return nil, err
	}
	defer clear(encoded)
	if err := s.Apple.Add(Service, account(name), label(name), encoded, synchronized); err != nil {
		record.Destroy()
		if errors.Is(err, keychain.ErrAlreadyExists) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create %s guardian %q: %w", provider, name, err)
	}
	return record, nil
}

func (s Store) Get(name guardian.Name, provider guardian.Provider) (*guardian.Record, error) {
	if _, err := guardian.ParseName(string(name)); err != nil {
		return nil, err
	}
	if provider == guardian.Environment {
		return s.getEnvironment(name)
	}
	synchronized, err := appleSynchronization(provider)
	if err != nil {
		return nil, err
	}
	if s.Apple == nil || runtime.GOOS != "darwin" {
		return nil, ErrUnsupported
	}
	data, err := s.Apple.Get(Service, account(name), synchronized)
	if errors.Is(err, keychain.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read %s guardian %q: %w", provider, name, err)
	}
	defer clear(data)
	return parseExpected(data, name)
}

func (s Store) Exists(name guardian.Name, provider guardian.Provider) (bool, error) {
	record, err := s.Get(name, provider)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	record.Destroy()
	return true, nil
}

func (s Store) List(provider guardian.Provider) ([]*guardian.Record, error) {
	if provider == guardian.Environment {
		value, ok := s.environmentValue()
		if !ok {
			return []*guardian.Record{}, nil
		}
		record, err := parseEnvironment(value)
		if err != nil {
			return nil, err
		}
		return []*guardian.Record{record}, nil
	}
	synchronized, err := appleSynchronization(provider)
	if err != nil {
		return nil, err
	}
	if s.Apple == nil || runtime.GOOS != "darwin" {
		return nil, ErrUnsupported
	}
	items, err := s.Apple.List(Service)
	if err != nil {
		return nil, fmt.Errorf("list Apple guardian records: %w", err)
	}
	defer func() {
		for index := range items {
			clear(items[index].Data)
		}
	}()
	records := make([]*guardian.Record, 0, len(items))
	for index := range items {
		item := &items[index]
		if item.Synchronizable != synchronized {
			clear(item.Data)
			continue
		}
		nameValue, ok := strings.CutPrefix(item.Account, "guardian:")
		if !ok {
			clear(item.Data)
			destroyRecords(records)
			return nil, fmt.Errorf("guardian Keychain account is malformed")
		}
		name, err := guardian.ParseName(nameValue)
		if err != nil {
			clear(item.Data)
			destroyRecords(records)
			return nil, err
		}
		record, err := parseExpected(item.Data, name)
		clear(item.Data)
		if err != nil {
			destroyRecords(records)
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name() < records[j].Name() })
	return records, nil
}

func (s Store) Delete(name guardian.Name, provider guardian.Provider) error {
	if _, err := guardian.ParseName(string(name)); err != nil {
		return err
	}
	if provider == guardian.Environment {
		return ErrReadOnly
	}
	synchronized, err := appleSynchronization(provider)
	if err != nil {
		return err
	}
	if s.Apple == nil || runtime.GOOS != "darwin" {
		return ErrUnsupported
	}
	if err := s.Apple.Delete(Service, account(name), synchronized); err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("delete %s guardian %q: %w", provider, name, err)
	}
	return nil
}

func (s Store) getEnvironment(expected guardian.Name) (*guardian.Record, error) {
	value, ok := s.environmentValue()
	if !ok {
		return nil, fmt.Errorf("%s is not set: %w", EnvironmentVariable, ErrNotFound)
	}
	record, err := parseEnvironment(value)
	if err != nil {
		return nil, err
	}
	if record.Name() != expected {
		record.Destroy()
		return nil, fmt.Errorf("environment guardian name does not match configured guardian")
	}
	return record, nil
}

func (s Store) environmentValue() (string, bool) {
	if s.LookupEnv == nil {
		return "", false
	}
	return s.LookupEnv(EnvironmentVariable)
}

func parseEnvironment(value string) (*guardian.Record, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("%s does not contain canonical unpadded base64url", EnvironmentVariable)
	}
	defer clear(decoded)
	record, err := guardian.ParseRecord(decoded)
	if err != nil {
		return nil, fmt.Errorf("parse %s guardian record: %w", EnvironmentVariable, err)
	}
	return record, nil
}

func parseExpected(data []byte, expected guardian.Name) (*guardian.Record, error) {
	record, err := guardian.ParseRecord(data)
	if err != nil {
		return nil, err
	}
	if record.Name() != expected {
		record.Destroy()
		return nil, fmt.Errorf("provider guardian name does not match its account")
	}
	return record, nil
}

func appleSynchronization(provider guardian.Provider) (bool, error) {
	switch provider {
	case guardian.AppleICloudKeychain:
		return true, nil
	case guardian.AppleLoginKeychain:
		return false, nil
	default:
		return false, fmt.Errorf("guardian provider %q is unsupported", provider)
	}
}

func account(name guardian.Name) string { return "guardian:" + string(name) }
func label(name guardian.Name) string   { return "Sphinx guardian “" + string(name) + "”" }
func destroyRecords(records []*guardian.Record) {
	for _, record := range records {
		record.Destroy()
	}
}

type nativeAppleBackend struct{}

func (nativeAppleBackend) Add(service, account, label string, data []byte, synchronized bool) error {
	return keychain.Add(service, account, label, data, synchronized)
}
func (nativeAppleBackend) Get(service, account string, synchronized bool) ([]byte, error) {
	return keychain.GetExact(service, account, synchronized)
}
func (nativeAppleBackend) List(service string) ([]KeychainItem, error) {
	items, err := keychain.List(service)
	if err != nil {
		return nil, err
	}
	out := make([]KeychainItem, len(items))
	for index, item := range items {
		out[index] = KeychainItem{Account: item.Account, Data: item.Data, Synchronizable: item.Synchronizable}
	}
	return out, nil
}
func (nativeAppleBackend) Delete(service, account string, synchronized bool) error {
	return keychain.DeleteExact(service, account, synchronized)
}
