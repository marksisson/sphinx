package schema

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/marksisson/sphinx/internal/yamlstrict"
)

const Directory = ".tomb/schemas"

var (
	namePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	fieldNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	referencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*/v[1-9][0-9]*$`)
)

type Definition struct {
	Version      int     `yaml:"version"`
	Name         string  `yaml:"name"`
	Description  string  `yaml:"description,omitempty"`
	Secrets      []Field `yaml:"secrets"`
	Inscriptions []Field `yaml:"inscriptions,omitempty"`
}

type Field struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Required bool     `yaml:"required"`
	Prompt   string   `yaml:"prompt"`
	Values   []string `yaml:"values,omitempty"`
}

type definitionWire struct {
	Version      int         `yaml:"version"`
	Name         string      `yaml:"name"`
	Description  string      `yaml:"description,omitempty"`
	Secrets      []fieldWire `yaml:"secrets"`
	Inscriptions []fieldWire `yaml:"inscriptions,omitempty"`
}

type fieldWire struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Required *bool    `yaml:"required"`
	Prompt   string   `yaml:"prompt"`
	Values   []string `yaml:"values,omitempty"`
}

func (d Definition) Reference() string {
	return fmt.Sprintf("%s/v%d", d.Name, d.Version)
}

func (f Field) Label() string { return f.Prompt }

func ValidateReference(reference string) error {
	if !referencePattern.MatchString(reference) {
		return fmt.Errorf("schema reference %q is invalid", reference)
	}
	return nil
}

// Decode parses one strict initial-format schema.
func Decode(data []byte) (*Definition, error) {
	var wire definitionWire
	if err := yamlstrict.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	definition := Definition{
		Version: wire.Version, Name: wire.Name, Description: wire.Description,
		Secrets: make([]Field, len(wire.Secrets)), Inscriptions: make([]Field, len(wire.Inscriptions)),
	}
	for index, field := range wire.Secrets {
		converted, err := convertField(field)
		if err != nil {
			return nil, fmt.Errorf("secret field %q: %w", field.Name, err)
		}
		definition.Secrets[index] = converted
	}
	for index, field := range wire.Inscriptions {
		converted, err := convertField(field)
		if err != nil {
			return nil, fmt.Errorf("inscription field %q: %w", field.Name, err)
		}
		definition.Inscriptions[index] = converted
	}
	if err := definition.Validate(); err != nil {
		return nil, err
	}
	return &definition, nil
}

func convertField(field fieldWire) (Field, error) {
	if field.Required == nil {
		return Field{}, fmt.Errorf("required is mandatory")
	}
	return Field{Name: field.Name, Type: field.Type, Required: *field.Required, Prompt: field.Prompt, Values: field.Values}, nil
}

func Load(root, reference string) (*Definition, error) {
	definitions, err := LoadAll(root)
	if err != nil {
		return nil, err
	}
	for index := range definitions {
		if definitions[index].Reference() == reference {
			return &definitions[index], nil
		}
	}
	return nil, fmt.Errorf("schema %q not found below %s", reference, filepath.Join(root, Directory))
}

func LoadAll(root string) ([]Definition, error) {
	directory := filepath.Join(root, Directory)
	var definitions []Definition
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("schema path %s is a symlink", path)
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		definition, err := Decode(data)
		if err != nil {
			return fmt.Errorf("schema %s: %w", path, err)
		}
		definitions = append(definitions, *definition)
		return nil
	})
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("schema directory %s does not exist", directory)
	}
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, definition := range definitions {
		if seen[definition.Reference()] {
			return nil, fmt.Errorf("duplicate schema %q", definition.Reference())
		}
		seen[definition.Reference()] = true
	}
	return definitions, nil
}

func (d Definition) Validate() error {
	if !namePattern.MatchString(d.Name) {
		return fmt.Errorf("schema name %q is invalid", d.Name)
	}
	if d.Version < 1 {
		return fmt.Errorf("schema version must be positive")
	}
	if len(d.Secrets) == 0 {
		return fmt.Errorf("at least one secret field is required")
	}
	seen := make(map[string]bool)
	for _, group := range [][]Field{d.Secrets, d.Inscriptions} {
		for _, field := range group {
			if !fieldNamePattern.MatchString(field.Name) {
				return fmt.Errorf("field name %q is invalid", field.Name)
			}
			if seen[field.Name] {
				return fmt.Errorf("field %q is duplicated", field.Name)
			}
			seen[field.Name] = true
			if field.Prompt == "" {
				return fmt.Errorf("field %q has no prompt", field.Name)
			}
			switch field.Type {
			case "string", "integer", "boolean":
				if field.Values != nil {
					return fmt.Errorf("field %q has values but is not an enum", field.Name)
				}
			case "enum":
				if len(field.Values) == 0 {
					return fmt.Errorf("enum field %q has no values", field.Name)
				}
				values := make(map[string]bool, len(field.Values))
				for _, value := range field.Values {
					if values[value] {
						return fmt.Errorf("enum field %q duplicates value %q", field.Name, value)
					}
					values[value] = true
				}
			default:
				return fmt.Errorf("field %q has unsupported type %q", field.Name, field.Type)
			}
		}
	}
	return nil
}

// ValidateArtifact validates the two inherent artifact value containers.
func (d Definition) ValidateArtifact(secrets, inscriptions map[string]any) error {
	if err := validateFields("secret", d.Secrets, secrets); err != nil {
		return err
	}
	return validateFields("inscription", d.Inscriptions, inscriptions)
}

func validateFields(group string, fields []Field, values map[string]any) error {
	allowed := make(map[string]Field, len(fields))
	for _, field := range fields {
		allowed[field.Name] = field
		value, exists := values[field.Name]
		if field.Required && (!exists || value == nil || value == "") {
			return fmt.Errorf("%s field %q is required", group, field.Name)
		}
		if exists {
			if err := validateValue(field, value); err != nil {
				return fmt.Errorf("%s field %q: %w", group, field.Name, err)
			}
		}
	}
	for name := range values {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("%s field %q is not defined by the schema", group, name)
		}
	}
	return nil
}

func validateValue(field Field, value any) error {
	switch field.Type {
	case "string", "enum":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("must be a string")
		}
		if field.Type == "enum" {
			for _, candidate := range field.Values {
				if text == candidate {
					return nil
				}
			}
			return fmt.Errorf("must be one of %s", strings.Join(field.Values, ", "))
		}
	case "integer":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		default:
			return fmt.Errorf("must be an integer")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("must be a boolean")
		}
	}
	return nil
}

func ParseValue(field Field, input string) (any, error) {
	switch field.Type {
	case "string", "enum":
		value := input
		if err := validateValue(field, value); err != nil {
			return nil, err
		}
		return value, nil
	case "integer":
		value, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("must be an integer")
		}
		return value, nil
	case "boolean":
		value, err := strconv.ParseBool(input)
		if err != nil {
			return nil, fmt.Errorf("must be true or false")
		}
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported type %q", field.Type)
	}
}
