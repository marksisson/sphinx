package tomb

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const SettingsVersion = 1

var tombName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Settings is the non-secret operational sphinx configuration.
type Settings struct {
	Version     int                     `yaml:"version"`
	DefaultTomb string                  `yaml:"default_tomb,omitempty"`
	Tombs       map[string]TombSettings `yaml:"tombs"`
}

type TombSettings struct {
	Locator   string           `yaml:"locator"`
	Lock      string           `yaml:"lock,omitempty"`
	Cache     string           `yaml:"cache,omitempty"`
	Decree    string           `yaml:"decree,omitempty"`
	Chronicle string           `yaml:"chronicle,omitempty"`
	Listen    string           `yaml:"listen,omitempty"`
	Guardian  GuardianSettings `yaml:"guardian,omitempty"`
}

type GuardianSettings struct {
	KeychainService string `yaml:"keychain_service,omitempty"`
	KeychainAccount string `yaml:"keychain_account,omitempty"`
}

// RuntimeSettings is a selected tomb with defaults and paths resolved.
type RuntimeSettings struct {
	Name       string
	Locator    Locator
	Ref        string
	Path       string
	Lock       string
	Cache      string
	Decree     string
	Chronicle  string
	Listen     string
	Guardian   GuardianSettings
	ConfigFile string
}

func DefaultSettingsPath() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "sphinx.yaml"
	}
	return filepath.Join(directory, "sphinx", "config.yaml")
}

// LoadSettings loads one named tomb. An empty name selects default_tomb, or
// the only configured tomb when there is exactly one.
func LoadSettings(filename, name string) (*RuntimeSettings, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("resolve sphinx configuration: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("inspect sphinx configuration %s: %w", absolute, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("sphinx configuration %s must be a regular file not writable by group or others", absolute)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, fmt.Errorf("read sphinx configuration %s: %w", absolute, err)
	}
	var settings Settings
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("parse sphinx configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("sphinx configuration contains multiple YAML documents")
		}
		return nil, fmt.Errorf("parse sphinx configuration: %w", err)
	}
	if settings.Version != SettingsVersion {
		return nil, fmt.Errorf("unsupported sphinx configuration version %d", settings.Version)
	}
	if len(settings.Tombs) == 0 {
		return nil, fmt.Errorf("sphinx configuration has no tombs")
	}
	if name == "" {
		name = settings.DefaultTomb
		if name == "" && len(settings.Tombs) == 1 {
			for candidate := range settings.Tombs {
				name = candidate
			}
		}
	}
	if !tombName.MatchString(name) {
		return nil, fmt.Errorf("invalid or missing tomb name %q", name)
	}
	configured, ok := settings.Tombs[name]
	if !ok {
		return nil, fmt.Errorf("tomb %q is not defined in %s", name, absolute)
	}
	if configured.Locator == "" {
		return nil, fmt.Errorf("tomb %q has no locator", name)
	}
	parsedLocator, err := ParseLocator(configured.Locator)
	if err != nil {
		return nil, fmt.Errorf("parse locator for tomb %q: %w", name, err)
	}
	_, tracking, selectedPath, err := parsedLocator.Select("", "")
	if err != nil {
		return nil, fmt.Errorf("configure tomb %q: %w", name, err)
	}
	base := filepath.Dir(absolute)
	cacheRoot, _ := os.UserCacheDir()
	resolved := &RuntimeSettings{
		Name: name, Locator: parsedLocator, Ref: tracking, Path: selectedPath,
		Lock:      resolveConfiguredPath(base, configured.Lock, name+".tomb.lock.yaml"),
		Cache:     resolveConfiguredPath(base, configured.Cache, filepath.Join(cacheRoot, "sphinx", "tombs")),
		Decree:    resolveConfiguredPath(base, configured.Decree, "decree.yaml"),
		Chronicle: resolveConfiguredPath(base, configured.Chronicle, name+".chronicle.jsonl"),
		Listen:    configured.Listen, Guardian: configured.Guardian, ConfigFile: absolute,
	}
	if resolved.Listen == "" {
		resolved.Listen = "127.0.0.1:8787"
	}
	return resolved, nil
}

func resolveConfiguredPath(base, configured, fallback string) string {
	value := configured
	if value == "" {
		value = fallback
	}
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
		}
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}
	return filepath.Clean(value)
}

// Lock pins a remote tomb configuration to one immutable Git commit.
type Lock struct {
	Version   int       `yaml:"version"`
	Tomb      string    `yaml:"tomb"`
	Locator   string    `yaml:"locator"`
	Revision  string    `yaml:"rev"`
	UpdatedAt time.Time `yaml:"updated_at"`
}

func LoadLock(filename string) (*Lock, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, fmt.Errorf("inspect tomb lock %s: %w", filename, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("tomb lock %s must be a regular file not writable by group or others", filename)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read tomb lock %s: %w", filename, err)
	}
	var lock Lock
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse tomb lock: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("tomb lock contains multiple YAML documents")
		}
		return nil, fmt.Errorf("parse tomb lock: %w", err)
	}
	if err := lock.Validate(); err != nil {
		return nil, err
	}
	return &lock, nil
}

func (l Lock) Validate() error {
	if l.Version != 1 {
		return fmt.Errorf("unsupported tomb lock version %d", l.Version)
	}
	if !tombName.MatchString(l.Tomb) || l.Locator == "" || !isFullRevision(l.Revision) {
		return fmt.Errorf("tomb lock is incomplete or invalid")
	}
	return nil
}

func (l Lock) Matches(settings *RuntimeSettings) error {
	if l.Tomb != settings.Name {
		return fmt.Errorf("tomb lock is for %q, not %q", l.Tomb, settings.Name)
	}
	if l.Locator != settings.Locator.String() {
		return fmt.Errorf("tomb lock locator %q does not match configured locator %q", l.Locator, settings.Locator.String())
	}
	return nil
}

func WriteLock(filename string, lock Lock) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(lock)
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create tomb lock directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".tomb.lock.*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filename)
}

func isFullRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
