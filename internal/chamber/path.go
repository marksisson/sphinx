// Package chamber defines exact, case-sensitive tomb chamber paths without
// performing filesystem or Git access.
package chamber

import (
	"fmt"
	"regexp"
	"strings"
)

const ArtifactFilename = "artifact.yaml"

var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Path is a validated slash-separated ASCII chamber path.
type Path struct {
	value string
}

// Parse validates the context-free chamber grammar. Filesystem and Git tree
// checks are intentionally performed by the locked-resource resolver.
func Parse(value string) (Path, error) {
	if value == "" {
		return Path{}, fmt.Errorf("chamber path is empty")
	}
	if strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") {
		return Path{}, fmt.Errorf("chamber path must be a relative slash-separated path")
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || !segmentPattern.MatchString(segment) {
			return Path{}, fmt.Errorf("invalid chamber segment %q", segment)
		}
		if segment == ".git" {
			return Path{}, fmt.Errorf("chamber path contains reserved .git segment")
		}
	}
	if segments[0] == ".tomb" {
		return Path{}, fmt.Errorf("chamber path uses reserved .tomb metadata root")
	}
	return Path{value: value}, nil
}

func (p Path) String() string { return p.value }

// ArtifactPath returns the canonical repository path. It never accepts a
// caller-supplied filename.
func (p Path) ArtifactPath() string {
	if p.value == "" {
		return ""
	}
	return p.value + "/" + ArtifactFilename
}
