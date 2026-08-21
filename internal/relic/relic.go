package relic

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

const FormatVersion = 1

var pathSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type Recovery struct {
	Type             string `yaml:"type" json:"type"`
	EncryptedDataKey string `yaml:"encrypted_data_key" json:"-"`
}

type Document struct {
	Format      int            `yaml:"format" json:"format"`
	Schema      string         `yaml:"schema" json:"schema"`
	Inscription map[string]any `yaml:"inscription,omitempty" json:"inscription,omitempty"`
	Essence     map[string]any `yaml:"essence" json:"essence"`
	Recovery    *Recovery      `yaml:"recovery,omitempty" json:"-"`
}

type Header struct {
	Format      int            `yaml:"format" json:"format"`
	Schema      string         `yaml:"schema" json:"schema"`
	Inscription map[string]any `yaml:"inscription,omitempty" json:"inscription,omitempty"`
}

func (d Document) ValidateHeader() error {
	if d.Format != FormatVersion {
		return fmt.Errorf("unsupported relic format %d", d.Format)
	}
	if d.Schema == "" {
		return fmt.Errorf("relic has no schema")
	}
	if d.Essence == nil {
		return fmt.Errorf("relic has no essence")
	}
	return nil
}

func MarshalPlain(document Document) ([]byte, error) {
	if err := document.ValidateHeader(); err != nil {
		return nil, err
	}
	return yaml.Marshal(document)
}

func ParsePlain(data []byte) (*Document, error) {
	var document Document
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse relic: %w", err)
	}
	if err := document.ValidateHeader(); err != nil {
		return nil, err
	}
	if document.Inscription == nil {
		document.Inscription = make(map[string]any)
	}
	return &document, nil
}

func ParseHeader(data []byte) (*Header, error) {
	var envelope struct {
		Format      int            `yaml:"format"`
		Schema      string         `yaml:"schema"`
		Inscription map[string]any `yaml:"inscription"`
	}
	if err := yaml.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parse relic header: %w", err)
	}
	if envelope.Format != FormatVersion {
		return nil, fmt.Errorf("unsupported relic format %d", envelope.Format)
	}
	if envelope.Schema == "" {
		return nil, fmt.Errorf("relic has no schema")
	}
	if envelope.Inscription == nil {
		envelope.Inscription = make(map[string]any)
	}
	return &Header{Format: envelope.Format, Schema: envelope.Schema, Inscription: envelope.Inscription}, nil
}

func ValidatePath(value string) error {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return fmt.Errorf("path is empty or absolute")
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || !pathSegment.MatchString(segment) {
			return fmt.Errorf("invalid path segment %q", segment)
		}
	}
	return nil
}

func Filename(root, relicPath string) (string, error) {
	if err := ValidatePath(relicPath); err != nil {
		return "", err
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return "", fmt.Errorf("resolve tomb: %w", err)
	}
	current := resolvedRoot
	for _, segment := range strings.Split(relicPath, "/") {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("relic path traverses symlink %s", current)
		}
	}
	return filepath.Join(current, "relic.yaml"), nil
}

func Read(root, relicPath string) ([]byte, error) {
	filename, err := Filename(root, relicPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read relic: %w", err)
	}
	return data, nil
}

func WriteAtomic(root, relicPath string, data []byte) error {
	filename, err := Filename(root, relicPath)
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create relic chamber: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".relic.yaml.*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
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
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	return nil
}

func Paths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || entry.Name() != "relic.yaml" {
			return nil
		}
		relative, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return paths, err
}
