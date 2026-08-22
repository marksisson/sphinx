package artifact

import (
	"os"
	"strings"
	"testing"

	"github.com/marksisson/sphinx/internal/hybridage"
)

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"format: 1\nschema: credential/v1\ninscriptions: {}\nsecrets:\n  token: value\n",
		"format: 1\nschema: x/v1\nsecrets: &values {token: value}\ninscriptions: *values\n",
		"format: 1\nschema: x/v1\ninscriptions: {}\nsecrets: !custom {token: value}\n",
		"format: 1\nformat: 1\nschema: x/v1\ninscriptions: {}\nsecrets: {token: value}\n",
		"format: 1\nschema: x/v1\ninscriptions: {}\nsecrets: {token: value}\n---\nformat: 1\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		document, err := Decode(input)
		if err != nil {
			return
		}
		defer document.Destroy()
		encoded, err := Encode(*document)
		if err != nil {
			t.Fatalf("accepted artifact cannot encode: %v", err)
		}
		roundTrip, err := Decode(encoded)
		if err != nil {
			t.Fatalf("encoded artifact cannot decode: %v", err)
		}
		roundTrip.Destroy()
	})
}

func FuzzSOPSMetadata(f *testing.F) {
	identityBytes, err := os.ReadFile("../../testdata/phase4/test-identities.txt")
	if err != nil {
		f.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(identityBytes)), "\n")
	identity, err := hybridage.ParseIdentity(strings.TrimPrefix(lines[1], "proclamation="))
	if err != nil {
		f.Fatal(err)
	}
	recipient := hybridage.Recipient(identity)
	fixture, err := os.ReadFile("../../testdata/phase4/proclamation-only.sops.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	for _, seed := range []string{
		"format: 1\nschema: x/v1\ninscriptions: {}\nsecrets: {}\nsops: {}\n",
		"format: 1\nschema: x/v1\ninscriptions: {}\nsecrets: {}\nsops: &metadata {}\ncopy: *metadata\n",
		"format: 1\nschema: x/v1\ninscriptions: {}\nsecrets: {}\nsops: !custom {}\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		inspection, err := (Engine{}).Inspect(input, recipient)
		if err != nil {
			return
		}
		if inspection.Verified || inspection.WarningCode != UnverifiedInscriptionCode || len(inspection.Recipients) == 0 || inspection.Recipients[0] != recipient {
			t.Fatalf("accepted SOPS metadata violated inspection contract: %#v", inspection)
		}
	})
}
