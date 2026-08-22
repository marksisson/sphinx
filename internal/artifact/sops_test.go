package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/marksisson/sphinx/internal/hybridage"
	"github.com/marksisson/sphinx/internal/schema"
	"go.yaml.in/yaml/v3"
)

func sopsFixtureSchema() schema.Definition {
	return schema.Definition{Version: 1, Name: "service", Secrets: []schema.Field{
		{Name: "api_key", Type: "string", Required: true, Prompt: "API key"},
		{Name: "replicas", Type: "integer", Required: true, Prompt: "Replicas"},
		{Name: "enabled", Type: "boolean", Required: true, Prompt: "Enabled"},
	}, Inscriptions: []schema.Field{
		{Name: "environment", Type: "enum", Required: true, Prompt: "Environment", Values: []string{"staging", "production"}},
		{Name: "owner", Type: "string", Required: false, Prompt: "Owner"},
	}}
}

func sopsFixtureDocument() Document {
	return Document{Format: 1, Schema: "service/v1", Inscriptions: map[string]any{"environment": "production", "owner": "platform"}, Secrets: map[string]any{"api_key": "secret-one", "replicas": 3, "enabled": true}}
}

func deterministicSOPSEngine() Engine {
	data := make([]byte, 32*16)
	for block := 0; block < 16; block++ {
		for index := 0; index < 32; index++ {
			data[block*32+index] = byte(block*37 + index + 1)
		}
	}
	return Engine{Random: bytes.NewReader(data), Now: func() time.Time { return time.Date(2026, 8, 22, 4, 5, 6, 0, time.UTC) }}
}

func TestSOPSFixtureChecksums(t *testing.T) {
	checksums := map[string]string{"multi-guardian.sops.yaml": "612d4ab548aa9f7f66725df830c61396a50384b616a88ed3093fb082ad840a97", "plain.yaml": "35e4018bd3d39521dd26da1428eccc2f8bce5639d8081e4721173ce59dec910f", "proclamation-only.sops.yaml": "f90d0b09fd64c7184ab598f48daf6d07bfa736e1bc455dc36a66df272795b690", "schema.yaml": "fd32233fc615a58c0b4e5c18690f47b405632df7d2c33d10a8fb1feb5619edda", "test-identities.txt": "098fda7fce1e00f40a0e59f7a53d4be45c391427d1fcc31e701db3146aac2838"}
	for name, want := range checksums {
		data, err := os.ReadFile("../../testdata/sops/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s checksum changed", name)
		}
	}
}

func TestSOPSMultiScalarFixtures(t *testing.T) {
	schemaBytes, err := os.ReadFile("../../testdata/sops/schema.yaml")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := schema.Decode(schemaBytes)
	if err != nil {
		t.Fatal(err)
	}
	identityBytes, err := os.ReadFile("../../testdata/sops/test-identities.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(identityBytes)), "\n")
	proclamation, err := hybridage.ParseIdentity(strings.TrimPrefix(lines[1], "proclamation="))
	if err != nil {
		t.Fatal(err)
	}
	guardian, err := hybridage.ParseIdentity(strings.TrimPrefix(lines[2], "guardian="))
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name       string
		identities []*age.HybridIdentity
		used       string
	}{{"proclamation-only.sops.yaml", []*age.HybridIdentity{proclamation}, proclamation.Recipient().String()}, {"multi-guardian.sops.yaml", []*age.HybridIdentity{guardian}, guardian.Recipient().String()}} {
		encrypted, err := os.ReadFile("../../testdata/sops/" + fixture.name)
		if err != nil {
			t.Fatal(err)
		}
		document, used, err := (Engine{}).DecryptWithIdentities(encrypted, proclamation.Recipient().String(), fixture.identities, *definition)
		if err != nil {
			t.Fatal(err)
		}
		if used != fixture.used || document.Secrets["api_key"] != "fixture-secret" || document.Secrets["replicas"] != 3 || document.Secrets["enabled"] != true || document.Inscriptions["owner"] != "platform" {
			t.Fatalf("%s = %#v via %q", fixture.name, document, used)
		}
	}
}

func TestPinnedExternalSOPSFixturePassesStrictEngine(t *testing.T) {
	encrypted, err := os.ReadFile("../../testdata/interoperability/artifact.sops.yaml")
	if err != nil {
		t.Fatal(err)
	}
	identityBytes, err := os.ReadFile("../../testdata/interoperability/hybrid-identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(identityBytes)), "\n")
	identity, err := hybridage.ParseIdentity(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	definition := schema.Definition{Version: 1, Name: "phase-zero", Secrets: []schema.Field{{Name: "api_key", Type: "string", Required: true, Prompt: "API key"}}, Inscriptions: []schema.Field{{Name: "environment", Type: "string", Required: true, Prompt: "Environment"}}}
	document, used, err := (Engine{}).DecryptWithIdentities(encrypted, identity.Recipient().String(), []*age.HybridIdentity{identity}, definition)
	if err != nil {
		t.Fatal(err)
	}
	if used != identity.Recipient().String() || document.Secrets["api_key"] != "phase-zero-secret" {
		t.Fatalf("fixture = %#v via %q", document, used)
	}
}

func TestCreateInspectDecryptAndRecipientFallback(t *testing.T) {
	proclamation, _ := hybridage.Generate()
	guardian, _ := hybridage.Generate()
	wrong, _ := hybridage.Generate()
	engine := deterministicSOPSEngine()
	encrypted, err := engine.Create(sopsFixtureDocument(), sopsFixtureSchema(), proclamation.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("secret-one")) {
		t.Fatal("encrypted artifact contains a plaintext secret")
	}
	inspection, err := engine.Inspect(encrypted, proclamation.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Verified || inspection.WarningCode != UnverifiedInscriptionCode || !strings.Contains(inspection.Warning, "MUST NOT") || inspection.Inscriptions["environment"] != "production" || len(inspection.RecipientFingerprints) != 1 {
		t.Fatalf("inspection = %#v", inspection)
	}
	document, used, err := engine.DecryptWithIdentities(encrypted, proclamation.Recipient().String(), []*age.HybridIdentity{proclamation}, sopsFixtureSchema())
	if err != nil {
		t.Fatal(err)
	}
	if used != proclamation.Recipient().String() || document.Secrets["api_key"] != "secret-one" {
		t.Fatalf("decrypted = %#v via %q", document, used)
	}

	withGuardian, err := engine.AddRecipient(encrypted, proclamation, sopsFixtureSchema(), guardian.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	assertAllCiphertextsChanged(t, encrypted, withGuardian)
	assertDataKeyChanged(t, encrypted, withGuardian, proclamation)
	document, used, err = engine.DecryptWithIdentities(withGuardian, proclamation.Recipient().String(), []*age.HybridIdentity{wrong, guardian}, sopsFixtureSchema())
	if err != nil {
		t.Fatal(err)
	}
	if used != guardian.Recipient().String() || document.Secrets["replicas"] != 3 {
		t.Fatalf("fallback used %q: %#v", used, document)
	}
	withoutGuardian, err := engine.RemoveRecipient(withGuardian, proclamation, sopsFixtureSchema(), guardian.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	assertAllCiphertextsChanged(t, withGuardian, withoutGuardian)
	assertDataKeyChanged(t, withGuardian, withoutGuardian, proclamation)
	if _, _, err := engine.DecryptWithIdentities(withoutGuardian, proclamation.Recipient().String(), []*age.HybridIdentity{guardian}, sopsFixtureSchema()); err == nil {
		t.Fatal("removed guardian still decrypted artifact")
	}
	if _, err := engine.AddRecipient(withGuardian, proclamation, sopsFixtureSchema(), guardian.Recipient().String()); err == nil {
		t.Fatal("duplicate guardian was accepted")
	}
}

func TestInscriptionAndResealAlwaysRotateDataKeyAndPreserveSchema(t *testing.T) {
	proclamation, _ := hybridage.Generate()
	engine := deterministicSOPSEngine()
	created, err := engine.Create(sopsFixtureDocument(), sopsFixtureSchema(), proclamation.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	inscribed, err := engine.SetInscription(created, proclamation, sopsFixtureSchema(), "environment", "staging")
	if err != nil {
		t.Fatal(err)
	}
	assertAllCiphertextsChanged(t, created, inscribed)
	assertDataKeyChanged(t, created, inscribed, proclamation)
	selected, err := engine.Reseal(inscribed, proclamation, sopsFixtureSchema(), "api_key", map[string]any{"api_key": "secret-two"})
	if err != nil {
		t.Fatal(err)
	}
	assertAllCiphertextsChanged(t, inscribed, selected)
	assertDataKeyChanged(t, inscribed, selected, proclamation)
	document, _, err := engine.DecryptWithIdentities(selected, proclamation.Recipient().String(), []*age.HybridIdentity{proclamation}, sopsFixtureSchema())
	if err != nil {
		t.Fatal(err)
	}
	if document.Secrets["api_key"] != "secret-two" || document.Secrets["replicas"] != 3 || document.Inscriptions["environment"] != "staging" || document.Schema != "service/v1" {
		t.Fatalf("selected reseal changed preserved values: %#v", document)
	}
	all := map[string]any{"api_key": "secret-three", "replicas": 7, "enabled": false}
	fully, err := engine.Reseal(selected, proclamation, sopsFixtureSchema(), "", all)
	if err != nil {
		t.Fatal(err)
	}
	assertAllCiphertextsChanged(t, selected, fully)
	assertDataKeyChanged(t, selected, fully, proclamation)
	document, _, err = engine.DecryptWithIdentities(fully, proclamation.Recipient().String(), []*age.HybridIdentity{proclamation}, sopsFixtureSchema())
	if err != nil || document.Secrets["replicas"] != 7 {
		t.Fatalf("full reseal = %#v, %v", document, err)
	}
}

func TestRejectsUnsupportedMetadataPlaintextSecretsWrongProclamationAndMACTampering(t *testing.T) {
	proclamation, _ := hybridage.Generate()
	other, _ := hybridage.Generate()
	engine := deterministicSOPSEngine()
	encrypted, err := engine.Create(sopsFixtureDocument(), sopsFixtureSchema(), proclamation.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"plaintext secret":   bytes.Replace(encrypted, secretCiphertexts(t, encrypted)[0], []byte("visible"), 1),
		"threshold":          bytes.Replace(encrypted, []byte("    age:\n"), []byte("    shamir_threshold: 2\n    age:\n"), 1),
		"alternate selector": bytes.Replace(encrypted, []byte("encrypted_regex: ^secrets$"), []byte("encrypted_regex: ^api_key$"), 1),
		"MAC tampering":      bytes.Replace(encrypted, []byte("data:"), []byte("data:X"), 1),
		"age envelope":       bytes.Replace(encrypted, []byte("-----BEGIN AGE ENCRYPTED FILE-----"), []byte("-----BEGIN OTHER FILE-----"), 1),
	}
	for name, altered := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := engine.DecryptWithIdentities(altered, proclamation.Recipient().String(), []*age.HybridIdentity{proclamation}, sopsFixtureSchema()); err == nil {
				t.Fatal("altered artifact accepted")
			}
		})
	}
	if _, err := engine.Inspect(encrypted, other.Recipient().String()); err == nil {
		t.Fatal("artifact accepted under the wrong proclamation")
	}
	guardianAuthored, err := engine.Create(sopsFixtureDocument(), sopsFixtureSchema(), other.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Inspect(guardianAuthored, proclamation.Recipient().String()); err == nil {
		t.Fatal("valid but proclamation-unlocked artifact accepted")
	}
}

func TestCreateRejectsNestedNullAndSequenceValues(t *testing.T) {
	proclamation, _ := hybridage.Generate()
	engine := deterministicSOPSEngine()
	for name, value := range map[string]any{"nested": map[string]any{"x": "y"}, "null": nil, "sequence": []any{"x"}} {
		document := sopsFixtureDocument()
		document.Secrets["api_key"] = value
		if _, err := engine.Create(document, sopsFixtureSchema(), proclamation.Recipient().String()); err == nil {
			t.Errorf("%s value accepted", name)
		}
	}
}

func secretCiphertexts(t *testing.T, encrypted []byte) [][]byte {
	t.Helper()
	var wire struct {
		Secrets map[string]string `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(encrypted, &wire); err != nil {
		t.Fatal(err)
	}
	result := make([][]byte, 0, len(wire.Secrets))
	for _, name := range []string{"api_key", "enabled", "replicas"} {
		result = append(result, []byte(wire.Secrets[name]))
	}
	return result
}
func assertDataKeyChanged(t *testing.T, before, after []byte, identity *age.HybridIdentity) {
	t.Helper()
	unwrap := func(encrypted []byte) []byte {
		_, tree, _, err := parseEncrypted(encrypted, identity.Recipient().String())
		if err != nil {
			t.Fatal(err)
		}
		key := tree.Metadata.KeyGroups[0][0].(*sopsage.MasterKey)
		if err := hybridage.ApplyIdentity(key, identity); err != nil {
			t.Fatal(err)
		}
		dataKey, err := key.Decrypt()
		if err != nil {
			t.Fatal(err)
		}
		return dataKey
	}
	first, second := unwrap(before), unwrap(after)
	defer clear(first)
	defer clear(second)
	if bytes.Equal(first, second) {
		t.Fatal("artifact mutation reused the SOPS data key")
	}
}

func assertAllCiphertextsChanged(t *testing.T, before, after []byte) {
	t.Helper()
	a, b := secretCiphertexts(t, before), secretCiphertexts(t, after)
	for i := range a {
		if bytes.Equal(a[i], b[i]) {
			t.Fatalf("secret ciphertext %d did not rotate", i)
		}
	}
}

func ExampleInspection() {
	fmt.Println(UnverifiedInscriptionCode)
	fmt.Println(UnverifiedInscriptionWarning)
	// Output:
	// unverified_inscriptions
	// UNVERIFIED: inscriptions have not been verified through the SOPS MAC and MUST NOT be trusted as authenticated artifact content.
}
