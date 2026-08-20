package policy

import (
	"fmt"
	"os"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Principal struct {
	Login string
	Node  string
	Tags  []string
}

type Policy struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	Name      string            `yaml:"name"`
	Paths     []string          `yaml:"paths"`
	Tailscale TailscaleIdentity `yaml:"tailscale"`
}

type TailscaleIdentity struct {
	Logins []string `yaml:"logins"`
	Tags   []string `yaml:"tags"`
}

func Load(filename string) (*Policy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var policy Policy
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if policy.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", policy.Version)
	}
	for index, rule := range policy.Rules {
		if rule.Name == "" {
			return nil, fmt.Errorf("rule %d has no name", index)
		}
		if len(rule.Paths) == 0 {
			return nil, fmt.Errorf("rule %q has no paths", rule.Name)
		}
		for _, pattern := range rule.Paths {
			if err := validatePattern(pattern); err != nil {
				return nil, fmt.Errorf("rule %q has invalid path pattern %q: %w", rule.Name, pattern, err)
			}
		}
	}
	return &policy, nil
}

func (p *Policy) Authorize(principal Principal, secretPath string) (bool, string) {
	for _, rule := range p.Rules {
		if !rule.matchesIdentity(principal) {
			continue
		}
		for _, pattern := range rule.Paths {
			matched, err := matchPath(pattern, secretPath)
			if err == nil && matched {
				return true, rule.Name
			}
		}
	}
	return false, "no matching policy rule"
}

func (r Rule) matchesIdentity(principal Principal) bool {
	for _, login := range r.Tailscale.Logins {
		if strings.EqualFold(strings.TrimSpace(login), principal.Login) {
			return true
		}
	}
	for _, allowedTag := range r.Tailscale.Tags {
		for _, actualTag := range principal.Tags {
			if allowedTag == actualTag {
				return true
			}
		}
	}
	return false
}

func validatePattern(pattern string) error {
	if pattern == "" || strings.HasPrefix(pattern, "/") || strings.HasSuffix(pattern, "/") {
		return fmt.Errorf("pattern is empty or absolute")
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("invalid pattern segment")
		}
		if segment == "**" {
			continue
		}
		if _, err := path.Match(segment, "validation"); err != nil {
			return err
		}
	}
	return nil
}

func matchPath(pattern, value string) (bool, error) {
	patternParts := strings.Split(pattern, "/")
	valueParts := strings.Split(value, "/")
	return matchParts(patternParts, valueParts)
}

func matchParts(pattern, value []string) (bool, error) {
	if len(pattern) == 0 {
		return len(value) == 0, nil
	}
	if pattern[0] == "**" {
		matched, err := matchParts(pattern[1:], value)
		if err != nil || matched {
			return matched, err
		}
		if len(value) == 0 {
			return false, nil
		}
		return matchParts(pattern, value[1:])
	}
	if len(value) == 0 {
		return false, nil
	}
	matched, err := path.Match(pattern[0], value[0])
	if err != nil || !matched {
		return false, err
	}
	return matchParts(pattern[1:], value[1:])
}
