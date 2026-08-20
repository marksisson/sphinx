package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndValidateDocument(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, Directory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	definition := `name: anthropic-api-key
version: 1
description: Anthropic API credential
essence:
  - name: api_key
    type: string
    required: true
    prompt: Anthropic API key
inscription:
  - name: environment
    type: enum
    values: [development, production]
    required: true
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
	if err := loaded.ValidateDocument(
		map[string]any{"api_key": "sk-ant-test"},
		map[string]any{"environment": "development"},
	); err != nil {
		t.Fatal(err)
	}
	if err := loaded.ValidateDocument(
		map[string]any{"api_key": "sk-ant-test"},
		map[string]any{"environment": "invalid"},
	); err == nil {
		t.Fatal("ValidateDocument unexpectedly accepted an invalid enum")
	}
}
