package decree

import "testing"

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"version: 1\ngeneration: 1\nartifact_locks: []\nschema_locks: []\nrules: []\n",
		"version: 1\ngeneration: 1\ngeneration: 2\nartifact_locks: []\nschema_locks: []\nrules: []\n",
		"version: 1\ngeneration: 1\nartifact_locks: &locks []\nschema_locks: *locks\nrules: []\n",
		"version: 1\ngeneration: 1\nartifact_locks: !custom []\nschema_locks: []\nrules: []\n",
		"version: 1\ngeneration: 1\nartifact_locks: []\nschema_locks: []\nrules: []\n---\nversion: 1\n",
		"defaults: &d {artifact_locks: [], schema_locks: [], rules: []}\nversion: 1\ngeneration: 1\n<<: *d\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		document, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := Encode(*document)
		if err != nil {
			t.Fatalf("accepted decree cannot encode: %v", err)
		}
		if _, err := Decode(encoded); err != nil {
			t.Fatalf("encoded decree cannot decode: %v", err)
		}
	})
}
