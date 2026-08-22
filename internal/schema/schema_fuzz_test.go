package schema

import (
	"testing"

	"github.com/marksisson/sphinx/internal/yamlstrict"
)

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n",
		"version: 1\nname: x\nname: y\nsecrets: []\n",
		"version: 1\nname: x\nsecrets: &fields []\ninscriptions: *fields\n",
		"version: 1\nname: x\nsecrets: !custom []\n",
		"version: 1\nname: x\nsecrets: []\n---\nversion: 2\n",
		"version: 1\nname: x\ndefaults: &d {type: string, required: true, prompt: X}\nsecrets:\n  - {name: token, <<: *d}\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		definition, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := yamlstrict.Marshal(*definition)
		if err != nil {
			t.Fatalf("accepted schema cannot encode: %v", err)
		}
		if _, err := Decode(encoded); err != nil {
			t.Fatalf("encoded schema cannot decode: %v", err)
		}
	})
}
