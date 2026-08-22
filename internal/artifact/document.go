// Package artifact defines the initial plaintext artifact domain model. SOPS
// encryption is layered on this model by the native SOPS engine.
package artifact

import (
	"fmt"
	"regexp"

	"github.com/marksisson/sphinx/internal/yamlstrict"
)

const FormatVersion = 1

var (
	schemaReferencePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*/v[1-9][0-9]*$`)
	fieldNamePattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Document is the exact top-level plaintext shape before SOPS processing.
type Document struct {
	Format       int            `yaml:"format" json:"format"`
	Schema       string         `yaml:"schema" json:"schema"`
	Inscriptions map[string]any `yaml:"inscriptions" json:"inscriptions"`
	Secrets      map[string]any `yaml:"secrets" json:"secrets"`
}

func Decode(data []byte) (*Document, error) {
	var document Document
	if err := yamlstrict.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse artifact: %w", err)
	}
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return &document, nil
}

func Encode(document Document) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return yamlstrict.Marshal(document)
}

// Destroy drops references to decrypted values. String scalar backing storage
// remains subject to Go runtime lifetime, but maps and mutable byte ownership
// are released as early as practical.
func (d *Document) Destroy() {
	if d == nil {
		return
	}
	for name := range d.Secrets {
		d.Secrets[name] = nil
		delete(d.Secrets, name)
	}
	for name := range d.Inscriptions {
		d.Inscriptions[name] = nil
		delete(d.Inscriptions, name)
	}
	d.Format = 0
	d.Schema = ""
	d.Secrets = nil
	d.Inscriptions = nil
}

func (d Document) Validate() error {
	if d.Format != FormatVersion {
		return fmt.Errorf("unsupported artifact format %d", d.Format)
	}
	if !schemaReferencePattern.MatchString(d.Schema) {
		return fmt.Errorf("artifact schema reference %q is invalid", d.Schema)
	}
	if d.Inscriptions == nil {
		return fmt.Errorf("artifact inscriptions mapping is required")
	}
	if len(d.Secrets) == 0 {
		return fmt.Errorf("artifact must contain at least one secret")
	}
	if err := validateValues("inscription", d.Inscriptions); err != nil {
		return err
	}
	return validateValues("secret", d.Secrets)
}

func validateValues(kind string, values map[string]any) error {
	for name, value := range values {
		if !fieldNamePattern.MatchString(name) {
			return fmt.Errorf("%s name %q is invalid", kind, name)
		}
		if !isScalar(value) {
			return fmt.Errorf("%s %q must be a non-null string, integer, or boolean scalar", kind, name)
		}
	}
	return nil
}

func isScalar(value any) bool {
	switch value.(type) {
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}
