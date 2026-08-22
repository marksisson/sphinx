package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndValidateArtifact(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, Directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	definition := `version: 1
name: anthropic-api-key
description: Anthropic API credential
secrets:
  - name: api_key
    type: string
    required: true
    prompt: Anthropic API key
inscriptions:
  - name: environment
    type: enum
    values: [development, production]
    required: true
    prompt: Deployment environment
`
	if err := os.WriteFile(filepath.Join(directory, "anthropic.yaml"), []byte(definition), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(root, "anthropic-api-key/v1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Reference() != "anthropic-api-key/v1" {
		t.Fatalf("Reference() = %q", loaded.Reference())
	}
	if err := loaded.ValidateArtifact(
		map[string]any{"api_key": "sk-ant-test"},
		map[string]any{"environment": "development"},
	); err != nil {
		t.Fatal(err)
	}
	if err := loaded.ValidateArtifact(
		map[string]any{"api_key": "sk-ant-test"},
		map[string]any{"environment": "invalid"},
	); err == nil {
		t.Fatal("ValidateArtifact unexpectedly accepted an invalid enum")
	}
}

func TestDecodeRejectsUnknownAndIncompleteFields(t *testing.T) {
	valid := "version: 1\nname: example\nsecrets:\n  - name: value\n    type: string\n    required: false\n    prompt: Value\n"
	for name, input := range map[string]string{
		"unknown top level": valid + "unknown: true\n",
		"unknown field":     "version: 1\nname: example\nsecrets:\n  - name: value\n    type: string\n    required: true\n    prompt: Value\n    unknown: true\n",
		"missing required":  "version: 1\nname: example\nsecrets:\n  - name: value\n    type: string\n    prompt: Value\n",
		"missing prompt":    "version: 1\nname: example\nsecrets:\n  - name: value\n    type: string\n    required: true\n",
		"duplicate enum":    "version: 1\nname: example\nsecrets:\n  - name: value\n    type: enum\n    values: [one, one]\n    required: true\n    prompt: Value\n",
		"legacy terms":      "version: 1\nname: example\nessence:\n  - name: value\n    type: string\n    required: true\n    prompt: Value\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("Decode unexpectedly succeeded")
			}
		})
	}
	if _, err := Decode([]byte(valid)); err != nil {
		t.Fatalf("valid schema failed: %v", err)
	}
}
