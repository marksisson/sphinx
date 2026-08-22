// Package strict enforces the syntax and byte-level invariants shared by
// every Sphinx-owned YAML format. Semantic validation remains with each domain
// package.
package strict

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Unmarshal decodes one strict Sphinx YAML document into out. It deliberately
// imposes no input-size limit.
func Unmarshal(data []byte, out any) error {
	if err := ValidateSyntax(data); err != nil {
		return err
	}

	known := yaml.NewDecoder(bytes.NewReader(data))
	known.KnownFields(true)
	if err := known.Decode(out); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	return nil
}

// ValidateSyntax checks framing and all format-independent YAML structure
// rules without applying a semantic known-field model.
func ValidateSyntax(data []byte) error {
	if err := ValidateBytes(data); err != nil {
		return err
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are forbidden")
		}
		return fmt.Errorf("decode YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return fmt.Errorf("YAML must contain exactly one document")
	}
	return validateNode(document.Content[0])
}

// Marshal emits canonical Sphinx YAML byte framing. Domain validation must run
// before Marshal is called.
func Marshal(value any) ([]byte, error) {
	data, err := yaml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode YAML: %w", err)
	}
	if err := ValidateBytes(data); err != nil {
		return nil, fmt.Errorf("encoder produced invalid YAML: %w", err)
	}
	return data, nil
}

// ValidateBytes checks UTF-8, BOM, line-ending, and final-newline rules.
func ValidateBytes(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("YAML document is empty")
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("YAML must be valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return fmt.Errorf("UTF-8 BOM is forbidden")
	}
	if bytes.ContainsRune(data, '\r') {
		return fmt.Errorf("YAML must use LF line endings")
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.HasSuffix(data, []byte("\n\n")) {
		return fmt.Errorf("YAML must end with exactly one LF")
	}
	return nil
}

func validateNode(node *yaml.Node) error {
	if node.Anchor != "" {
		return fmt.Errorf("YAML anchors are forbidden")
	}
	if node.Kind == yaml.AliasNode || node.Alias != nil {
		return fmt.Errorf("YAML aliases are forbidden")
	}
	if len(node.Tag) > 0 && node.Tag[0] == '!' && (len(node.Tag) < 2 || node.Tag[1] != '!') {
		return fmt.Errorf("custom YAML tags are forbidden")
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("YAML mapping keys must be strings")
			}
			if key.Value == "<<" {
				return fmt.Errorf("YAML merge keys are forbidden")
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}
