package gitresource

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/marksisson/sphinx/internal/chamber"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/yamlstrict"
)

var (
	schemaPathPattern   = regexp.MustCompile(`^\.tomb/schemas/([a-z][a-z0-9-]*)/(v[1-9][0-9]*)\.yaml$`)
	rotationPathPattern = regexp.MustCompile(`^\.tomb/rotations/([0-9]{8})(\.yaml|\.from\.sig|\.to\.sig)$`)
)

type RotationBlobs struct {
	Transition Blob
	From       Blob
	To         Blob
}

type Content struct {
	Artifacts map[string]Blob
	Schemas   map[string]Blob
	Rotations map[int]RotationBlobs
	Manifest  Blob
	Decree    Blob
	Signature Blob
}

// ValidateContent validates the Phase 2 public Git layout and every managed
// entry directly from the approved commit's object database.
func (r *Repository) ValidateContent(ctx context.Context) (*Content, error) {
	entries, err := r.ListTree(ctx)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]TreeEntry, len(entries))
	for _, entry := range entries {
		if _, exists := byPath[entry.Path]; exists {
			return nil, fmt.Errorf("duplicate Git tree path %q", entry.Path)
		}
		byPath[entry.Path] = entry
	}
	content := &Content{Artifacts: make(map[string]Blob), Schemas: make(map[string]Blob), Rotations: make(map[int]RotationBlobs)}
	rotations := make(map[int]uint8)
	required := []string{".tomb/tomb.yaml", ".tomb/decree.yaml", ".tomb/decree.yaml.sig", ".tomb/rotations/.keep"}
	for _, name := range required {
		blob, err := r.ReadBlob(ctx, name)
		if err != nil {
			return nil, err
		}
		if name != ".tomb/rotations/.keep" {
			if err := yamlstrict.ValidateSyntax(blob.Data); err != nil {
				return nil, fmt.Errorf("managed YAML %q: %w", name, err)
			}
		}
		switch name {
		case ".tomb/tomb.yaml":
			content.Manifest = blob
		case ".tomb/decree.yaml":
			content.Decree = blob
		case ".tomb/decree.yaml.sig":
			content.Signature = blob
		case ".tomb/rotations/.keep":
			if len(blob.Data) != 0 {
				return nil, fmt.Errorf(".tomb/rotations/.keep must be a zero-byte Git blob")
			}
		}
	}

	for _, entry := range entries {
		if !utf8.ValidString(entry.Path) {
			continue // unrelated Git paths need not be UTF-8
		}
		if strings.HasPrefix(entry.Path, ".tomb/") {
			if isRequired(entry.Path, required) {
				continue
			}
			if strings.HasPrefix(entry.Path, ".tomb/rotations/") {
				matches := rotationPathPattern.FindStringSubmatch(entry.Path)
				if matches == nil {
					return nil, fmt.Errorf("non-sequence rotation path %q is forbidden", entry.Path)
				}
				sequence, _ := strconv.Atoi(matches[1])
				if sequence == 0 {
					return nil, fmt.Errorf("rotation sequence must start at one")
				}
				mask := uint8(1)
				if matches[2] == ".from.sig" {
					mask = 2
				} else if matches[2] == ".to.sig" {
					mask = 4
				}
				rotations[sequence] |= mask
				blob, err := r.ReadBlob(ctx, entry.Path)
				if err != nil {
					return nil, err
				}
				if err := yamlstrict.ValidateSyntax(blob.Data); err != nil {
					return nil, fmt.Errorf("managed YAML %q: %w", entry.Path, err)
				}
				group := content.Rotations[sequence]
				switch matches[2] {
				case ".yaml":
					group.Transition = blob
				case ".from.sig":
					group.From = blob
				case ".to.sig":
					group.To = blob
				}
				content.Rotations[sequence] = group
				continue
			}
			matches := schemaPathPattern.FindStringSubmatch(entry.Path)
			if matches == nil {
				return nil, fmt.Errorf("unsupported or non-canonical tomb metadata path %q", entry.Path)
			}
			blob, err := r.ReadBlob(ctx, entry.Path)
			if err != nil {
				return nil, err
			}
			definition, err := schema.Decode(blob.Data)
			if err != nil {
				return nil, fmt.Errorf("schema blob %q: %w", entry.Path, err)
			}
			reference := matches[1] + "/" + matches[2]
			if definition.Reference() != reference {
				return nil, fmt.Errorf("schema blob %q declares %q", entry.Path, definition.Reference())
			}
			content.Schemas[reference] = blob
			continue
		}
		base := path.Base(entry.Path)
		if base == "tomb.yaml" || base == "decree.yaml" || base == "decree.yaml.sig" {
			return nil, fmt.Errorf("alternate tomb metadata path %q is forbidden", entry.Path)
		}
		if base != chamber.ArtifactFilename {
			continue
		}
		chamberPath, err := chamber.Parse(path.Dir(entry.Path))
		if err != nil {
			return nil, fmt.Errorf("invalid committed chamber for %q: %w", entry.Path, err)
		}
		blob, err := r.ReadBlob(ctx, entry.Path)
		if err != nil {
			return nil, err
		}
		if err := yamlstrict.ValidateSyntax(blob.Data); err != nil {
			return nil, fmt.Errorf("managed YAML %q: %w", entry.Path, err)
		}
		content.Artifacts[chamberPath.String()] = blob
	}
	if len(content.Schemas) == 0 {
		return nil, fmt.Errorf("tomb contains no canonical schemas")
	}
	for sequence := 1; sequence <= len(rotations); sequence++ {
		if rotations[sequence] != 7 {
			return nil, fmt.Errorf("rotation sequence %08d is missing, incomplete, or non-contiguous", sequence)
		}
	}
	return content, nil
}

func isRequired(name string, required []string) bool {
	for _, candidate := range required {
		if name == candidate {
			return true
		}
	}
	return false
}
