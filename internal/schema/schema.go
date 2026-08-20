package schema

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const Directory = ".sphinx/schemas"

type Definition struct {
	Name        string  `yaml:"name"`
	Version     int     `yaml:"version"`
	Description string  `yaml:"description,omitempty"`
	Essence     []Field `yaml:"essence"`
	Inscription []Field `yaml:"inscription,omitempty"`
}

type Field struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Prompt   string   `yaml:"prompt,omitempty"`
	Required bool     `yaml:"required,omitempty"`
	Values   []string `yaml:"values,omitempty"`
}

func (d Definition) Reference() string {
	return fmt.Sprintf("%s/v%d", d.Name, d.Version)
}

func (f Field) Label() string {
	if f.Prompt != "" {
		return f.Prompt
	}
	return strings.ReplaceAll(f.Name, "_", " ")
}

func Load(root, reference string) (*Definition, error) {
	definitions, err := LoadAll(root)
	if err != nil {
		return nil, err
	}
	for i := range definitions {
		if definitions[i].Reference() == reference {
			return &definitions[i], nil
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
		if entry.IsDir() || (filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var definition Definition
		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&definition); err != nil {
			return fmt.Errorf("parse schema %s: %w", path, err)
		}
		if err := definition.Validate(); err != nil {
			return fmt.Errorf("validate schema %s: %w", path, err)
		}
		definitions = append(definitions, definition)
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
	if d.Name == "" || strings.ContainsAny(d.Name, "/\\") {
		return fmt.Errorf("name must be a non-empty single path segment")
	}
	if d.Version < 1 {
		return fmt.Errorf("version must be positive")
	}
	if len(d.Essence) == 0 {
		return fmt.Errorf("at least one Essence field is required")
	}
	seen := make(map[string]bool)
	for _, group := range [][]Field{d.Essence, d.Inscription} {
		for _, field := range group {
			if field.Name == "" || strings.ContainsAny(field.Name, ". /\\") {
				return fmt.Errorf("field name %q is invalid", field.Name)
			}
			if seen[field.Name] {
				return fmt.Errorf("field %q is duplicated", field.Name)
			}
			seen[field.Name] = true
			switch field.Type {
			case "string", "integer", "boolean":
				if len(field.Values) != 0 {
					return fmt.Errorf("field %q has values but is not an enum", field.Name)
				}
			case "enum":
				if len(field.Values) == 0 {
					return fmt.Errorf("enum field %q has no values", field.Name)
				}
			default:
				return fmt.Errorf("field %q has unsupported type %q", field.Name, field.Type)
			}
		}
	}
	return nil
}

func (d Definition) ValidateDocument(essence, inscription map[string]any) error {
	if err := validateFields("Essence", d.Essence, essence); err != nil {
		return err
	}
	return validateFields("Inscription", d.Inscription, inscription)
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
		case int, int64, uint64:
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
