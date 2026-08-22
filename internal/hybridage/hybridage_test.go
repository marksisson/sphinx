package hybridage

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"filippo.io/age"
	sopsage "github.com/getsops/sops/v3/age"
)

func TestNativeHybridRoundTripAndSOPSInjection(t *testing.T) {
	identity, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	parsedIdentity, err := ParseIdentity(identity.String())
	if err != nil {
		t.Fatal(err)
	}
	recipient := Recipient(parsedIdentity)
	parsedRecipient, err := ParseRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	stanzas, labels, err := parsedRecipient.WrapWithLabels(make([]byte, 16))
	if err != nil || len(stanzas) != 1 || stanzas[0].Type != "mlkem768x25519" || len(stanzas[0].Args) != 1 || len(labels) != 1 || labels[0] != "postquantum" {
		t.Fatalf("native hybrid stanza/labels = %#v, %#v, %v", stanzas, labels, err)
	}
	if fingerprint, err := Fingerprint(recipient); err != nil || !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Fatalf("Fingerprint = %q, %v", fingerprint, err)
	}

	key, err := MasterKey(recipient)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyIdentity(key, parsedIdentity); err != nil {
		t.Fatal(err)
	}
	dataKey := []byte("01234567890123456789012345678901")
	if err := key.Encrypt(dataKey); err != nil {
		t.Fatal(err)
	}
	decrypted, err := key.Decrypt()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, dataKey) {
		t.Fatal("SOPS master key round trip changed the data key")
	}
}

func TestIdentityFromSeedUsesNativeAgeEncoding(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString("j6NydUQYVTETs95C4VTZbdMn2z6munLwsqrzH0hsTG0")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := IdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := "AGE-SECRET-KEY-PQ-1373HYA2YRP2NZYANMEPWZ4XEDHFJ0KE756A89U9J4TE37JRVF3KSTHKLAC"
	if identity.String() != want {
		t.Fatalf("seed-derived identity = %q, want %q", identity.String(), want)
	}
	fingerprint, err := Fingerprint(identity.Recipient().String())
	if err != nil || fingerprint != "SHA256:WWtXGRhtWNgLc78hW37MrSkkVtmnWr24PS7mG6ukTtE" {
		t.Fatalf("seed-derived recipient fingerprint = %q, %v", fingerprint, err)
	}
}

func TestRejectsNonHybridAndNonCanonicalEncodings(t *testing.T) {
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := Generate()
	for _, value := range []string{x25519.String(), "AGE-PLUGIN-TEST-1QQQQ", " " + identity.String(), strings.ToLower(identity.String())} {
		if _, err := ParseIdentity(value); err == nil {
			t.Errorf("ParseIdentity accepted %q", value)
		}
	}
	for _, value := range []string{x25519.Recipient().String(), "age1test1qqqq", " " + identity.Recipient().String(), strings.ToUpper(identity.Recipient().String())} {
		if _, err := ParseRecipient(value); err == nil {
			t.Errorf("ParseRecipient accepted %q", value)
		}
	}
	if err := ApplyIdentity(&sopsage.MasterKey{Recipient: x25519.Recipient().String()}, identity); err == nil {
		t.Fatal("ApplyIdentity accepted a classical SOPS master key")
	}
}
