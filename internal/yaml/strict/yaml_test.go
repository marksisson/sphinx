package strict

import (
	"strings"
	"testing"
)

type testDocument struct {
	Version int `yaml:"version"`
	Nested  struct {
		Name string `yaml:"name"`
	} `yaml:"nested"`
}

func TestUnmarshalStrictDocument(t *testing.T) {
	var document testDocument
	if err := Unmarshal([]byte("version: 1\nnested:\n  name: sphinx\n"), &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != 1 || document.Nested.Name != "sphinx" {
		t.Fatalf("unexpected document: %#v", document)
	}
}

func TestUnmarshalRejectsNonStrictYAML(t *testing.T) {
	tests := map[string][]byte{
		"empty":              {},
		"invalid UTF-8":      {0xff, '\n'},
		"BOM":                []byte("\xef\xbb\xbfversion: 1\n"),
		"CRLF":               []byte("version: 1\r\n"),
		"missing final LF":   []byte("version: 1"),
		"two final LFs":      []byte("version: 1\n\n"),
		"unknown field":      []byte("version: 1\nunknown: true\n"),
		"duplicate top key":  []byte("version: 1\nversion: 1\n"),
		"duplicate deep key": []byte("version: 1\nnested:\n  name: one\n  name: two\n"),
		"anchor":             []byte("version: &v 1\nnested:\n  name: sphinx\n"),
		"alias":              []byte("version: &v 1\nnested:\n  name: *v\n"),
		"custom tag":         []byte("version: !integer 1\n"),
		"merge key":          []byte("version: 1\nnested:\n  <<: {name: sphinx}\n"),
		"multiple documents": []byte("version: 1\n---\nversion: 1\n"),
		"non-string key":     []byte("version: 1\nnested:\n  1: value\n"),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var document testDocument
			if err := Unmarshal(input, &document); err == nil {
				t.Fatal("Unmarshal unexpectedly succeeded")
			}
		})
	}
}

func TestValidateSyntaxRejectsAmbiguousStructureWithoutSemanticModel(t *testing.T) {
	for _, input := range []string{
		"value: &anchor one\n",
		"value: !custom one\n",
		"value: one\nvalue: two\n",
		"value: one\n---\nvalue: two\n",
	} {
		if err := ValidateSyntax([]byte(input)); err == nil {
			t.Errorf("ValidateSyntax(%q) unexpectedly succeeded", input)
		}
	}
	if err := ValidateSyntax([]byte("arbitrary: structure\n")); err != nil {
		t.Fatalf("ValidateSyntax rejected strict YAML: %v", err)
	}
}

func TestMarshalUsesStrictFraming(t *testing.T) {
	data, err := Marshal(struct {
		Version int `yaml:"version"`
	}{Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "version: 1\n" {
		t.Fatalf("Marshal = %q", got)
	}
	if strings.HasSuffix(string(data), "\n\n") {
		t.Fatal("Marshal emitted more than one final LF")
	}
}
