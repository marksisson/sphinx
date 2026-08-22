// Package config implements read-only global tomb aliases and project-local
// approved tomb locks.
package config

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	gitrepository "github.com/marksisson/sphinx/internal/git/repository"
	"github.com/marksisson/sphinx/internal/guardian"
	"github.com/marksisson/sphinx/internal/locator"
	"github.com/marksisson/sphinx/internal/safefile"
	yamlstrict "github.com/marksisson/sphinx/internal/yaml/strict"
	"golang.org/x/sys/unix"
)

const Version = 1
const ProjectRelativePath = ".sphinx/config.yaml"

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Global struct {
	Version int                   `yaml:"version"`
	Tombs   map[string]GlobalTomb `yaml:"tombs"`
}

type GlobalTomb struct {
	Reference string `yaml:"reference"`
}

type Project struct {
	Version int                    `yaml:"version"`
	Tombs   map[string]ProjectTomb `yaml:"tombs"`
}

type ProjectTomb struct {
	Reference string              `yaml:"reference"`
	Lock      Lock                `yaml:"lock"`
	Guardians []GuardianSelection `yaml:"guardians,omitempty"`
}

type Lock struct {
	Commit                  string    `yaml:"commit"`
	ProclamationFingerprint string    `yaml:"proclamation_fingerprint"`
	DecreeGeneration        uint64    `yaml:"decree_generation"`
	LockedAt                time.Time `yaml:"-"`
}

type GuardianSelection struct {
	Name     guardian.Name     `yaml:"name"`
	Provider guardian.Provider `yaml:"provider,omitempty"`
}

type projectWire struct {
	Version int                        `yaml:"version"`
	Tombs   map[string]projectTombWire `yaml:"tombs"`
}

type projectTombWire struct {
	Reference string                  `yaml:"reference"`
	Lock      lockWire                `yaml:"lock"`
	Guardians []guardianSelectionWire `yaml:"guardians,omitempty"`
}

type lockWire struct {
	Commit                  string  `yaml:"commit"`
	ProclamationFingerprint string  `yaml:"proclamation_fingerprint"`
	DecreeGeneration        *uint64 `yaml:"decree_generation"`
	LockedAt                string  `yaml:"locked_at"`
}

type guardianSelectionWire struct {
	Name     string `yaml:"name"`
	Provider string `yaml:"provider,omitempty"`
}

func GlobalPath() (string, error) {
	root := os.Getenv("XDG_CONFIG_HOME")
	if root == "" || !filepath.IsAbs(root) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		root = filepath.Join(home, ".config")
	}
	return filepath.Join(root, "sphinx", "config.yaml"), nil
}

// LoadGlobal loads the optional manually managed alias file. A missing file
// returns an empty valid configuration.
func LoadGlobal(ctx context.Context, filename, cwd string) (*Global, error) {
	data, err := readSafeConfig(filename, true)
	if os.IsNotExist(err) {
		return &Global{Version: Version, Tombs: map[string]GlobalTomb{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var global Global
	if err := yamlstrict.Unmarshal(data, &global); err != nil {
		return nil, fmt.Errorf("parse global Sphinx configuration: %w", err)
	}
	if global.Version != Version {
		return nil, fmt.Errorf("unsupported global configuration version %d", global.Version)
	}
	if global.Tombs == nil {
		return nil, fmt.Errorf("global configuration tombs mapping is required")
	}
	canonical := make(map[string]string, len(global.Tombs))
	for name, tomb := range global.Tombs {
		if err := ValidateAlias(name); err != nil {
			return nil, err
		}
		reference, err := locator.ParseAt(ctx, tomb.Reference, cwd)
		if err != nil {
			return nil, fmt.Errorf("global tomb %q: %w", name, err)
		}
		global.Tombs[name] = GlobalTomb{Reference: reference.String()}
		if previous := canonical[reference.String()]; previous != "" {
			return nil, fmt.Errorf("global tombs %q and %q duplicate canonical reference %q", previous, name, reference.String())
		}
		canonical[reference.String()] = name
	}
	return &global, nil
}

func DecodeProject(ctx context.Context, data []byte, cwd string) (*Project, error) {
	var wire projectWire
	if err := yamlstrict.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("parse project Sphinx configuration: %w", err)
	}
	if wire.Version != Version {
		return nil, fmt.Errorf("unsupported project configuration version %d", wire.Version)
	}
	if wire.Tombs == nil {
		return nil, fmt.Errorf("project configuration tombs mapping is required")
	}
	project := &Project{Version: Version, Tombs: make(map[string]ProjectTomb, len(wire.Tombs))}
	environmentGuardians := 0
	canonical := make(map[string]string, len(wire.Tombs))
	for name, tombWire := range wire.Tombs {
		if err := ValidateAlias(name); err != nil {
			return nil, err
		}
		reference, err := locator.ParseAt(ctx, tombWire.Reference, cwd)
		if err != nil {
			return nil, fmt.Errorf("project tomb %q: %w", name, err)
		}
		if previous := canonical[reference.String()]; previous != "" {
			return nil, fmt.Errorf("project tombs %q and %q duplicate canonical reference %q", previous, name, reference.String())
		}
		canonical[reference.String()] = name
		lock, err := decodeLock(tombWire.Lock)
		if err != nil {
			return nil, fmt.Errorf("project tomb %q: %w", name, err)
		}
		selections := make([]GuardianSelection, len(tombWire.Guardians))
		seenGuardians := make(map[guardian.Name]bool, len(tombWire.Guardians))
		for index, selection := range tombWire.Guardians {
			guardianName, err := guardian.ParseName(selection.Name)
			if err != nil {
				return nil, fmt.Errorf("project tomb %q: %w", name, err)
			}
			providerName := selection.Provider
			if providerName == "" {
				defaultProvider, err := guardian.DefaultProvider()
				if err != nil {
					return nil, err
				}
				providerName = string(defaultProvider)
			}
			provider, err := guardian.ParseProvider(providerName)
			if err != nil {
				return nil, fmt.Errorf("project tomb %q: %w", name, err)
			}
			if seenGuardians[guardianName] {
				return nil, fmt.Errorf("project tomb %q duplicates guardian name %q", name, guardianName)
			}
			if provider == guardian.Environment {
				environmentGuardians++
				if environmentGuardians > 1 {
					return nil, fmt.Errorf("project configuration selects more than one environment guardian")
				}
			}
			seenGuardians[guardianName] = true
			selections[index] = GuardianSelection{Name: guardianName, Provider: provider}
		}
		project.Tombs[name] = ProjectTomb{Reference: reference.String(), Lock: lock, Guardians: selections}
	}
	return project, nil
}

func EncodeProject(project Project) ([]byte, error) {
	if project.Version != Version {
		return nil, fmt.Errorf("unsupported project configuration version %d", project.Version)
	}
	if project.Tombs == nil {
		return nil, fmt.Errorf("project configuration tombs mapping is required")
	}
	wire := projectWire{Version: Version, Tombs: make(map[string]projectTombWire, len(project.Tombs))}
	environmentGuardians := 0
	canonical := make(map[string]string, len(project.Tombs))
	for name, tomb := range project.Tombs {
		if err := ValidateAlias(name); err != nil {
			return nil, err
		}
		reference, err := locator.Parse(tomb.Reference)
		if err != nil {
			return nil, err
		}
		if previous := canonical[reference.String()]; previous != "" {
			return nil, fmt.Errorf("project tombs %q and %q duplicate canonical reference %q", previous, name, reference.String())
		}
		canonical[reference.String()] = name
		if err := tomb.Lock.Validate(); err != nil {
			return nil, err
		}
		guardians := make([]guardianSelectionWire, len(tomb.Guardians))
		seenGuardians := make(map[guardian.Name]bool, len(tomb.Guardians))
		for index, selection := range tomb.Guardians {
			if _, err := guardian.ParseName(string(selection.Name)); err != nil {
				return nil, err
			}
			provider := selection.Provider
			if provider == "" {
				var err error
				provider, err = guardian.DefaultProvider()
				if err != nil {
					return nil, err
				}
			}
			if _, err := guardian.ParseProvider(string(provider)); err != nil {
				return nil, err
			}
			if seenGuardians[selection.Name] {
				return nil, fmt.Errorf("project tomb %q duplicates guardian name %q", name, selection.Name)
			}
			if provider == guardian.Environment {
				environmentGuardians++
				if environmentGuardians > 1 {
					return nil, fmt.Errorf("project configuration selects more than one environment guardian")
				}
			}
			seenGuardians[selection.Name] = true
			guardians[index] = guardianSelectionWire{Name: string(selection.Name), Provider: string(provider)}
		}
		generation := tomb.Lock.DecreeGeneration
		wire.Tombs[name] = projectTombWire{
			Reference: reference.String(),
			Lock: lockWire{Commit: tomb.Lock.Commit, ProclamationFingerprint: tomb.Lock.ProclamationFingerprint,
				DecreeGeneration: &generation, LockedAt: tomb.Lock.LockedAt.UTC().Format(time.RFC3339Nano)},
			Guardians: guardians,
		}
	}
	return yamlstrict.Marshal(wire)
}

func decodeLock(wire lockWire) (Lock, error) {
	if wire.DecreeGeneration == nil {
		return Lock{}, fmt.Errorf("decree_generation is required")
	}
	lockedAt, err := time.Parse(time.RFC3339Nano, wire.LockedAt)
	if err != nil || !strings.HasSuffix(wire.LockedAt, "Z") {
		return Lock{}, fmt.Errorf("locked_at must be an RFC3339 UTC timestamp")
	}
	lock := Lock{Commit: wire.Commit, ProclamationFingerprint: wire.ProclamationFingerprint,
		DecreeGeneration: *wire.DecreeGeneration, LockedAt: lockedAt}
	return lock, lock.Validate()
}

func (l Lock) Validate() error {
	if !locator.IsFullRevision(l.Commit) {
		return fmt.Errorf("lock commit is not a full lowercase Git commit ID")
	}
	encoded := strings.TrimPrefix(l.ProclamationFingerprint, "SHA256:")
	digest, err := base64.RawURLEncoding.DecodeString(encoded)
	if !strings.HasPrefix(l.ProclamationFingerprint, "SHA256:") || err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != encoded {
		return fmt.Errorf("lock proclamation fingerprint is invalid")
	}
	if l.LockedAt.IsZero() || l.LockedAt.Location() != time.UTC {
		return fmt.Errorf("lock timestamp must be nonzero UTC")
	}
	return nil
}

func ValidateAlias(name string) error {
	if !aliasPattern.MatchString(name) {
		return fmt.Errorf("tomb alias %q is invalid", name)
	}
	return nil
}

// ResolveEnrollment resolves an exact global alias or a direct reference and
// derives the enrollment name when no override is supplied.
func ResolveEnrollment(ctx context.Context, target, nameOverride string, global *Global, cwd string) (string, locator.Locator, error) {
	var reference locator.Locator
	var err error
	defaultName := ""
	if alias, found := global.Tombs[target]; found {
		reference, err = locator.ParseAt(ctx, alias.Reference, cwd)
		defaultName = target
	} else {
		reference, err = locator.ParseAt(ctx, target, cwd)
		defaultName = reference.DefaultName()
	}
	if err != nil {
		return "", locator.Locator{}, err
	}
	name := nameOverride
	if name == "" {
		name = defaultName
	}
	if err := ValidateAlias(name); err != nil {
		return "", locator.Locator{}, err
	}
	return name, reference, nil
}

// Select resolves an omitted selector to exactly default, an exact project
// alias, or a direct reference canonically matching one project lock.
func (p Project) Select(ctx context.Context, selector, cwd string) (string, ProjectTomb, error) {
	if selector == "" {
		selector = "default"
	}
	if tomb, found := p.Tombs[selector]; found {
		return selector, tomb, nil
	}
	reference, err := locator.ParseAt(ctx, selector, cwd)
	if err != nil {
		return "", ProjectTomb{}, fmt.Errorf("project tomb %q is neither an alias nor a valid reference", selector)
	}
	for name, tomb := range p.Tombs {
		if tomb.Reference == reference.String() {
			return name, tomb, nil
		}
	}
	return "", ProjectTomb{}, fmt.Errorf("tomb reference %q does not match a project lock", reference.String())
}

func readSafeConfig(filename string, optional bool) ([]byte, error) {
	parentInfo, err := os.Lstat(filepath.Dir(filename))
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("inspect configuration directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("configuration directory must be a non-symlink directory")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("configuration must be a regular non-symlink file not writable by group or others")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("configuration is not owned by the current user")
	}
	return os.ReadFile(filename)
}

// Store represents the nearest Git worktree's project configuration.
type Store struct {
	Root     string
	GitDir   string
	Filename string
	cwd      string
}

func Discover(ctx context.Context, start string) (*Store, error) {
	resolved, err := filepath.EvalSymlinks(start)
	if err != nil {
		return nil, fmt.Errorf("resolve project location: %w", err)
	}
	worktree, err := gitrepository.DiscoverWorktree(ctx, resolved)
	if err != nil {
		return nil, fmt.Errorf("discover project Git worktree: %w", err)
	}
	root, gitDir := worktree.Root, worktree.GitDir
	sphinxDirectory := filepath.Join(root, ".sphinx")
	if info, err := os.Lstat(sphinxDirectory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("project .sphinx must be a non-symlink directory")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return &Store{Root: root, GitDir: gitDir, Filename: filepath.Join(root, ProjectRelativePath), cwd: resolved}, nil
}

func (s *Store) Load(ctx context.Context, optional bool) (*Project, error) {
	data, err := readSafeConfig(s.Filename, optional)
	if optional && os.IsNotExist(err) {
		return &Project{Version: Version, Tombs: map[string]ProjectTomb{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return DecodeProject(ctx, data, s.cwd)
}

// Update serializes project-config writers through the Git administrative
// directory and atomically replaces only .sphinx/config.yaml.
func (s *Store) Update(ctx context.Context, change func(*Project) error) error {
	lockPath := filepath.Join(s.GitDir, "sphinx-project-config.lock")
	lockFD, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open non-symlink project configuration lock: %w", err)
	}
	lockFile := os.NewFile(uintptr(lockFD), lockPath)
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock project configuration: %w", err)
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck
	project, err := s.Load(ctx, true)
	if err != nil {
		return err
	}
	if err := change(project); err != nil {
		return err
	}
	data, err := EncodeProject(*project)
	if err != nil {
		return err
	}
	directory := filepath.Join(s.Root, ".sphinx")
	if info, err := os.Lstat(directory); os.IsNotExist(err) {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return fmt.Errorf("create project configuration directory: %w", err)
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("project configuration directory is unsafe")
	}
	return safefile.WriteAtomicWithin(s.Root, ProjectRelativePath, data, 0o600)
}

func (s *Store) Add(ctx context.Context, name string, tomb ProjectTomb) error {
	if err := ValidateAlias(name); err != nil {
		return err
	}
	reference, err := locator.ParseAt(ctx, tomb.Reference, s.cwd)
	if err != nil {
		return err
	}
	tomb.Reference = reference.String()
	if err := tomb.Lock.Validate(); err != nil {
		return err
	}
	return s.Update(ctx, func(project *Project) error {
		if _, exists := project.Tombs[name]; exists {
			return fmt.Errorf("project tomb alias %q already exists", name)
		}
		for existingName, existing := range project.Tombs {
			if existing.Reference == tomb.Reference {
				return fmt.Errorf("project tomb %q already uses reference %q", existingName, tomb.Reference)
			}
		}
		project.Tombs[name] = tomb
		return nil
	})
}

type LockProposal struct {
	Name           string
	ExpectedCommit string
	Lock           Lock
	Validate       func(context.Context) error
}

// UpdateLocks validates every proposal while holding the project lock and then
// performs one atomic config replacement, or changes nothing.
func (s *Store) UpdateLocks(ctx context.Context, proposals []LockProposal) error {
	if len(proposals) == 0 {
		return nil
	}
	return s.Update(ctx, func(project *Project) error {
		seen := make(map[string]bool, len(proposals))
		for _, proposal := range proposals {
			if seen[proposal.Name] {
				return fmt.Errorf("duplicate lock proposal for project tomb %q", proposal.Name)
			}
			seen[proposal.Name] = true
			tomb, exists := project.Tombs[proposal.Name]
			if !exists {
				return fmt.Errorf("project tomb %q does not exist", proposal.Name)
			}
			if tomb.Lock.Commit != proposal.ExpectedCommit {
				return fmt.Errorf("project tomb %q lock changed concurrently", proposal.Name)
			}
			if err := proposal.Lock.Validate(); err != nil {
				return err
			}
			if proposal.Validate != nil {
				if err := proposal.Validate(ctx); err != nil {
					return fmt.Errorf("validate project tomb %q candidate: %w", proposal.Name, err)
				}
			}
		}
		for _, proposal := range proposals {
			tomb := project.Tombs[proposal.Name]
			tomb.Lock = proposal.Lock
			project.Tombs[proposal.Name] = tomb
		}
		return nil
	})
}
