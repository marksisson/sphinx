package artifact

import "testing"

func TestDecodeInitialArtifact(t *testing.T) {
	document, err := Decode([]byte("format: 1\nschema: anthropic-api-key/v1\ninscriptions:\n  environment: production\nsecrets:\n  api_key: secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if document.Secrets["api_key"] != "secret" || document.Inscriptions["environment"] != "production" {
		t.Fatalf("unexpected document: %#v", document)
	}
	encoded, err := Encode(*document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("encoded artifact did not decode: %v", err)
	}
}

func TestDecodeRejectsInvalidArtifact(t *testing.T) {
	tests := map[string]string{
		"unknown top-level field": "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets: {value: x}\nextra: true\n",
		"wrong format":            "format: 2\nschema: example/v1\ninscriptions: {}\nsecrets: {value: x}\n",
		"bad schema":              "format: 1\nschema: ../example\ninscriptions: {}\nsecrets: {value: x}\n",
		"missing inscriptions":    "format: 1\nschema: example/v1\nsecrets: {value: x}\n",
		"empty secrets":           "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets: {}\n",
		"null secret":             "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets: {value: null}\n",
		"nested secret":           "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets:\n  value: {nested: no}\n",
		"sequence inscription":    "format: 1\nschema: example/v1\ninscriptions: {owners: [one, two]}\nsecrets: {value: x}\n",
		"float":                   "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets: {value: 1.5}\n",
		"invalid field name":      "format: 1\nschema: example/v1\ninscriptions: {}\nsecrets: {bad-name: x}\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("Decode unexpectedly succeeded")
			}
		})
	}
}
