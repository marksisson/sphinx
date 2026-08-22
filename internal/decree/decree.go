// Package decree implements the strict version-1 allow-only reveal policy and
// exhaustive committed-blob locks.
package decree

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/marksisson/sphinx/internal/chamber"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/seeker"
	yamlstrict "github.com/marksisson/sphinx/internal/yaml/strict"
)

const Version = 1

var (
	digestPattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	patternSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9._*-]+$`)
)

type ArtifactLock struct {
	Chamber string `yaml:"chamber"`
	SHA256  string `yaml:"sha256"`
}

type SchemaLock struct {
	Schema string `yaml:"schema"`
	SHA256 string `yaml:"sha256"`
}

type Selectors struct {
	Logins []string `yaml:"logins"`
	Tags   []string `yaml:"tags"`
}

type Rule struct {
	Name      string    `yaml:"name"`
	Seekers   Selectors `yaml:"seekers"`
	Artifacts []string  `yaml:"artifacts"`
}

type Document struct {
	Version       int            `yaml:"version"`
	Generation    uint64         `yaml:"generation"`
	ArtifactLocks []ArtifactLock `yaml:"artifact_locks"`
	SchemaLocks   []SchemaLock   `yaml:"schema_locks"`
	Rules         []Rule         `yaml:"rules"`
}

type wire struct {
	Version       int            `yaml:"version"`
	Generation    *uint64        `yaml:"generation"`
	ArtifactLocks []ArtifactLock `yaml:"artifact_locks"`
	SchemaLocks   []SchemaLock   `yaml:"schema_locks"`
	Rules         []Rule         `yaml:"rules"`
}

func Decode(data []byte) (*Document, error) {
	document, err := DecodeDraft(data)
	if err != nil {
		return nil, err
	}
	if err := document.Validate(); err != nil {
		return nil, err
	}
	return document, nil
}

// DecodeDraft applies strict syntax and known-field validation while leaving
// generation and lock semantics to the proclamation-authorized decree signer.
func DecodeDraft(data []byte) (*Document, error) {
	var value wire
	if err := yamlstrict.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("parse decree: %w", err)
	}
	if value.Generation == nil {
		return nil, fmt.Errorf("decree generation is required")
	}
	return &Document{Version: value.Version, Generation: *value.Generation, ArtifactLocks: value.ArtifactLocks, SchemaLocks: value.SchemaLocks, Rules: value.Rules}, nil
}

func Encode(document Document) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	generation := document.Generation
	return yamlstrict.Marshal(wire{Version: document.Version, Generation: &generation, ArtifactLocks: document.ArtifactLocks, SchemaLocks: document.SchemaLocks, Rules: document.Rules})
}

func (d Document) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("unsupported decree version %d", d.Version)
	}
	if d.Generation == 0 {
		return fmt.Errorf("decree generation must be positive")
	}
	if d.ArtifactLocks == nil || d.SchemaLocks == nil || d.Rules == nil {
		return fmt.Errorf("decree lock lists and rules are required")
	}
	artifacts := make(map[string]bool, len(d.ArtifactLocks))
	for index, lock := range d.ArtifactLocks {
		parsed, err := chamber.Parse(lock.Chamber)
		if err != nil || parsed.String() != lock.Chamber {
			return fmt.Errorf("artifact lock %d has invalid chamber %q", index, lock.Chamber)
		}
		if !digestPattern.MatchString(lock.SHA256) {
			return fmt.Errorf("artifact lock %q has invalid SHA-256", lock.Chamber)
		}
		if artifacts[lock.Chamber] || index > 0 && d.ArtifactLocks[index-1].Chamber >= lock.Chamber {
			return fmt.Errorf("artifact locks must be unique and bytewise sorted")
		}
		artifacts[lock.Chamber] = true
	}
	schemas := make(map[string]bool, len(d.SchemaLocks))
	for index, lock := range d.SchemaLocks {
		if err := schema.ValidateReference(lock.Schema); err != nil {
			return fmt.Errorf("schema lock %d: %w", index, err)
		}
		if !digestPattern.MatchString(lock.SHA256) {
			return fmt.Errorf("schema lock %q has invalid SHA-256", lock.Schema)
		}
		if schemas[lock.Schema] || index > 0 && d.SchemaLocks[index-1].Schema >= lock.Schema {
			return fmt.Errorf("schema locks must be unique and bytewise sorted")
		}
		schemas[lock.Schema] = true
	}
	ruleNames := make(map[string]bool, len(d.Rules))
	for index, rule := range d.Rules {
		if !ruleNamePattern.MatchString(rule.Name) || ruleNames[rule.Name] {
			return fmt.Errorf("decree rule %d has an invalid or duplicate name %q", index, rule.Name)
		}
		ruleNames[rule.Name] = true
		if rule.Seekers.Logins == nil || rule.Seekers.Tags == nil || len(rule.Seekers.Logins)+len(rule.Seekers.Tags) == 0 {
			return fmt.Errorf("decree rule %q requires at least one login or tag and both selector lists", rule.Name)
		}
		if err := validateSelectors(rule.Name, rule.Seekers); err != nil {
			return err
		}
		if len(rule.Artifacts) == 0 {
			return fmt.Errorf("decree rule %q requires at least one artifact pattern", rule.Name)
		}
		seenPatterns := map[string]bool{}
		for _, pattern := range rule.Artifacts {
			if seenPatterns[pattern] {
				return fmt.Errorf("decree rule %q duplicates artifact pattern %q", rule.Name, pattern)
			}
			seenPatterns[pattern] = true
			if err := ValidatePattern(pattern); err != nil {
				return fmt.Errorf("decree rule %q: %w", rule.Name, err)
			}
			matched := false
			for locked := range artifacts {
				if Match(pattern, locked) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("decree rule %q pattern %q matches no locked artifact", rule.Name, pattern)
			}
		}
	}
	return nil
}

func validateSelectors(rule string, selectors Selectors) error {
	seen := map[string]bool{}
	for _, login := range selectors.Logins {
		if login == "" || login != strings.TrimSpace(login) || seen["login\x00"+login] {
			return fmt.Errorf("decree rule %q has an invalid or duplicate login", rule)
		}
		seen["login\x00"+login] = true
	}
	for _, tag := range selectors.Tags {
		if !strings.HasPrefix(tag, "tag:") || len(tag) == 4 || tag != strings.TrimSpace(tag) || seen["tag\x00"+tag] {
			return fmt.Errorf("decree rule %q has an invalid or duplicate tag", rule)
		}
		seen["tag\x00"+tag] = true
	}
	return nil
}

func ValidatePattern(pattern string) error {
	if pattern == "" || strings.HasPrefix(pattern, "/") || strings.HasSuffix(pattern, "/") || strings.ContainsAny(pattern, "?[]{}\\") {
		return fmt.Errorf("artifact pattern %q is invalid", pattern)
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("artifact pattern %q has an invalid segment", pattern)
		}
		if !patternSegmentPattern.MatchString(segment) {
			return fmt.Errorf("artifact pattern %q has unsupported segment characters", pattern)
		}
		if segment != "**" && strings.Contains(segment, "**") {
			return fmt.Errorf("artifact pattern %q uses partial-segment **", pattern)
		}
		for _, character := range []byte(segment) {
			if character < 0x21 || character > 0x7e {
				return fmt.Errorf("artifact pattern %q is not printable ASCII", pattern)
			}
		}
	}
	return nil
}

// Match performs an anchored, case-sensitive match. A ** segment consumes zero
// or more complete chamber segments; * consumes characters within one segment.
func Match(pattern, value string) bool {
	if ValidatePattern(pattern) != nil {
		return false
	}
	parts, target := strings.Split(pattern, "/"), strings.Split(value, "/")
	memo := map[[2]int]bool{}
	seen := map[[2]int]bool{}
	var match func(int, int) bool
	match = func(pi, vi int) bool {
		key := [2]int{pi, vi}
		if seen[key] {
			return memo[key]
		}
		seen[key] = true
		if pi == len(parts) {
			memo[key] = vi == len(target)
			return memo[key]
		}
		if parts[pi] == "**" {
			memo[key] = match(pi+1, vi) || vi < len(target) && match(pi, vi+1)
			return memo[key]
		}
		memo[key] = vi < len(target) && matchSegment(parts[pi], target[vi]) && match(pi+1, vi+1)
		return memo[key]
	}
	return match(0, 0)
}

func matchSegment(pattern, value string) bool {
	positions := make([]bool, len(value)+1)
	positions[0] = true
	for _, character := range []byte(pattern) {
		next := make([]bool, len(value)+1)
		if character == '*' {
			active := false
			for index := 0; index <= len(value); index++ {
				active = active || positions[index]
				next[index] = active
			}
		} else {
			for index := 0; index < len(value); index++ {
				next[index+1] = positions[index] && value[index] == character
			}
		}
		positions = next
	}
	return positions[len(value)]
}

func (d Document) Authorizes(identity seeker.Identity, chamberPath string) bool {
	for _, rule := range d.Rules {
		identityMatch := identity.Login != "" && contains(rule.Seekers.Logins, identity.Login)
		if !identityMatch {
			for _, tag := range identity.Tags {
				if contains(rule.Seekers.Tags, tag) {
					identityMatch = true
					break
				}
			}
		}
		if !identityMatch {
			continue
		}
		for _, pattern := range rule.Artifacts {
			if Match(pattern, chamberPath) {
				return true
			}
		}
	}
	return false
}

func contains(values []string, selected string) bool {
	index := sort.SearchStrings(values, selected)
	if index < len(values) && values[index] == selected {
		return true
	}
	for _, value := range values {
		if value == selected {
			return true
		}
	}
	return false
}
