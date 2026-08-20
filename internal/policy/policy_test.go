package policy

import "testing"

func TestAuthorize(t *testing.T) {
	access := &Policy{Version: 1, Rules: []Rule{
		{
			Name:  "developer-ai",
			Paths: []string{"openai/**", "anthropic/*/api/*"},
			Tailscale: TailscaleIdentity{
				Logins: []string{"developer@example.com"},
			},
		},
		{
			Name:  "production-node",
			Paths: []string{"aws/production/**"},
			Tailscale: TailscaleIdentity{
				Tags: []string{"tag:production"},
			},
		},
	}}

	tests := []struct {
		name      string
		principal Principal
		path      string
		allowed   bool
	}{
		{"login match", Principal{Login: "developer@example.com"}, "openai/api/key", true},
		{"login case insensitive", Principal{Login: "Developer@Example.com"}, "anthropic/claude/api/key", true},
		{"wrong path", Principal{Login: "developer@example.com"}, "aws/production/key", false},
		{"tag match", Principal{Tags: []string{"tag:production"}}, "aws/production/database/password", true},
		{"empty identity", Principal{}, "openai/api/key", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allowed, _ := access.Authorize(test.principal, test.path)
			if allowed != test.allowed {
				t.Fatalf("Authorize() = %v, want %v", allowed, test.allowed)
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{"**", "openai/**", "anthropic/*/api/?ey"}
	for _, pattern := range valid {
		if err := validatePattern(pattern); err != nil {
			t.Errorf("validatePattern(%q): %v", pattern, err)
		}
	}
	invalid := []string{"", "/absolute", "trailing/", "a//b", "a/../b", "a/["}
	for _, pattern := range invalid {
		if err := validatePattern(pattern); err == nil {
			t.Errorf("validatePattern(%q) unexpectedly succeeded", pattern)
		}
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"**", "a/b/c", true},
		{"a/**/c", "a/b/d/c", true},
		{"a/**/c", "a/c", true},
		{"a/*/c", "a/b/c", true},
		{"a/*/c", "a/b/d/c", false},
		{"a/?", "a/b", true},
		{"a/b", "a/b/c", false},
	}
	for _, test := range tests {
		matched, err := matchPath(test.pattern, test.value)
		if err != nil {
			t.Fatalf("matchPath(%q, %q): %v", test.pattern, test.value, err)
		}
		if matched != test.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", test.pattern, test.value, matched, test.want)
		}
	}
}
