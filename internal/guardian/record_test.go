package guardian

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/hybridage"
)

func TestRecordCanonicalRoundTripAndDerivedMetadata(t *testing.T) {
	name, _ := ParseName("production")
	identity, err := hybridage.Generate()
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewRecord(name, identity, time.Date(2026, 8, 21, 1, 2, 3, 4, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer record.Destroy()
	if fmt.Sprintf("%v", record) != "[REDACTED GUARDIAN RECORD]" || fmt.Sprintf("%#v", record) != "[REDACTED GUARDIAN RECORD]" {
		t.Fatal("guardian record formatting exposed private material")
	}
	encoded, err := record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	if parsed.Name() != name || parsed.Recipient() != identity.Recipient().String() || !strings.HasPrefix(parsed.Fingerprint(), "SHA256:") {
		t.Fatal("parsed guardian record metadata differs")
	}
	parsedIdentity, err := parsed.Identity()
	if err != nil || parsedIdentity.String() != identity.String() {
		t.Fatal("parsed guardian identity differs")
	}
}

func TestRecordRejectsNoncanonicalCorruptAndUnknownJSON(t *testing.T) {
	name, _ := ParseName("guardian")
	record, err := GenerateRecord(name, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer record.Destroy()
	encoded, _ := record.MarshalJSON()

	pretty := append([]byte(" "), encoded...)
	duplicate := bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	unknown := bytes.Replace(encoded, []byte(`"name":`), []byte(`"unknown":1,"name":`), 1)
	mismatch := bytes.Replace(encoded, []byte(record.Fingerprint()), []byte("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 1)
	for name, input := range map[string][]byte{"pretty": pretty, "duplicate": duplicate, "unknown": unknown, "mismatch": mismatch, "trailing": append(encoded, '\n')} {
		if _, err := ParseRecord(input); err == nil {
			t.Errorf("ParseRecord accepted %s JSON", name)
		}
	}
}
