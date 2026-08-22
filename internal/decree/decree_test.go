package decree

import (
	"strings"
	"testing"

	"github.com/marksisson/sphinx/internal/seeker"
)

const digestA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const digestB = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validDocument() Document {
	return Document{Version: 1, Generation: 7,
		ArtifactLocks: []ArtifactLock{{Chamber: "Production/API", SHA256: digestA}, {Chamber: "production/db", SHA256: digestB}},
		SchemaLocks:   []SchemaLock{{Schema: "credential/v1", SHA256: digestA}},
		Rules:         []Rule{{Name: "operators", Seekers: Selectors{Logins: []string{"alice@example.com"}, Tags: []string{"tag:ci"}}, Artifacts: []string{"**/API", "production/**"}}},
	}
}

func TestEncodeDecodeAndAuthorization(t *testing.T) {
	document := validDocument()
	encoded, err := Encode(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	login, _ := seeker.New("alice@example.com", nil)
	if !decoded.Authorizes(login, "production/db") {
		t.Fatal("login seeker was denied")
	}
	tag, _ := seeker.New("", []string{"tag:ci"})
	if !decoded.Authorizes(tag, "Production/API") {
		t.Fatal("tag-only seeker was denied")
	}
	other, _ := seeker.New("bob@example.com", []string{"tag:other"})
	if decoded.Authorizes(other, "production/db") {
		t.Fatal("unmatched seeker was authorized")
	}
	if decoded.Authorizes(login, "Production/api") {
		t.Fatal("case-folded chamber was authorized")
	}
}

func TestGlobGrammar(t *testing.T) {
	matches := map[string][]string{
		"**": {"one", "one/two"}, "production/**": {"production", "production/a", "production/a/b"},
		"*/api": {"x/api"}, "a*b": {"ab", "axxb"},
	}
	for pattern, values := range matches {
		for _, value := range values {
			if !Match(pattern, value) {
				t.Errorf("%q did not match %q", pattern, value)
			}
		}
	}
	for _, pattern := range []string{"", "/a", "a/", "a/**b", "a/?", "a/[x]", `a\\b`, "a//b"} {
		if ValidatePattern(pattern) == nil {
			t.Errorf("invalid pattern %q accepted", pattern)
		}
	}
}

func TestStrictPolicyAndLocks(t *testing.T) {
	base, err := Encode(validDocument())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"deny field": func(data []byte) []byte {
			return []byte(strings.Replace(string(data), "name: operators", "name: operators\n    deny: true", 1))
		},
		"action field": func(data []byte) []byte {
			return []byte(strings.Replace(string(data), "name: operators", "name: operators\n    action: reveal", 1))
		},
		"duplicate key": func(data []byte) []byte { return append([]byte("version: 1\n"), data...) },
		"unsigned generation": func(data []byte) []byte {
			return []byte(strings.Replace(string(data), "generation: 7\n", "generation: -1\n", 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(mutate(base)); err == nil {
				t.Fatal("malformed decree accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*Document){
		"unsorted artifacts": func(d *Document) { d.ArtifactLocks[0], d.ArtifactLocks[1] = d.ArtifactLocks[1], d.ArtifactLocks[0] },
		"duplicate selector": func(d *Document) { d.Rules[0].Seekers.Tags = []string{"tag:ci", "tag:ci"} },
		"unmatched pattern":  func(d *Document) { d.Rules[0].Artifacts = []string{"absent/**"} },
		"zero selectors":     func(d *Document) { d.Rules[0].Seekers = Selectors{Logins: []string{}, Tags: []string{}} },
	} {
		t.Run(name, func(t *testing.T) {
			d := validDocument()
			mutate(&d)
			if d.Validate() == nil {
				t.Fatal("invalid decree accepted")
			}
		})
	}
}
