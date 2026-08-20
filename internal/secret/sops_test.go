package secret

import (
	"context"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestValueDecryptsAgeSOPSAndVerifiesMAC(t *testing.T) {
	identity, err := os.ReadFile("testdata/identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile("testdata/age.yaml")
	if err != nil {
		t.Fatal(err)
	}

	decrypter, err := NewDecrypter(strings.TrimSpace(string(identity)))
	if err != nil {
		t.Fatal(err)
	}
	value, err := decrypter.Value(context.Background(), encrypted)
	if err != nil {
		t.Fatalf("Value(): %v", err)
	}
	if value != "integration-test-value" {
		t.Fatalf("Value() = %#v, want integration-test-value", value)
	}
}

func TestEncryptSupportsOnlineAndPassphraseRecovery(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("format: 1\nschema: example/v1\ninscription:\n  owner: platform\nessence:\n  api_key: secret-value\n")
	encrypted, err := Encrypt(plaintext, identity.Recipient().String(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "secret-value") || strings.Contains(string(encrypted), "correct horse battery staple") {
		t.Fatal("encrypted Relic contains secret material")
	}
	if !strings.Contains(string(encrypted), "owner: platform") || !strings.Contains(string(encrypted), "age-scrypt-v1") {
		t.Fatal("encrypted Relic does not retain protected metadata and recovery envelope")
	}

	decrypter, err := NewDecrypter(identity.String())
	if err != nil {
		t.Fatal(err)
	}
	online, err := decrypter.Plain(context.Background(), encrypted)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := DecryptRecovery(encrypted, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if string(online) != string(recovery) || !strings.Contains(string(online), "api_key: secret-value") {
		t.Fatalf("online and recovery plaintext differ:\n%s\n%s", online, recovery)
	}
	if _, err := DecryptRecovery(encrypted, "wrong passphrase"); err == nil {
		t.Fatal("recovery unexpectedly accepted the wrong passphrase")
	}
	otherIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecipients(encrypted, otherIdentity.Recipient().String()); err == nil {
		t.Fatal("recipient validation unexpectedly accepted another online identity")
	}
}

func TestValueRejectsModifiedCiphertext(t *testing.T) {
	identity, err := os.ReadFile("testdata/identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile("testdata/age.yaml")
	if err != nil {
		t.Fatal(err)
	}

	marker := []byte("integration-test-value")
	if strings.Contains(string(encrypted), string(marker)) {
		t.Fatal("fixture unexpectedly contains plaintext")
	}
	index := strings.Index(string(encrypted), "data:")
	if index < 0 {
		t.Fatal("fixture has no encrypted data")
	}
	modified := append([]byte(nil), encrypted...)
	for index < len(modified) && modified[index] != ',' {
		index++
	}
	if index+1 >= len(modified) {
		t.Fatal("could not locate ciphertext")
	}
	modified[index-1] ^= 1

	decrypter, err := NewDecrypter(strings.TrimSpace(string(identity)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decrypter.Value(context.Background(), modified); err == nil {
		t.Fatal("Value() unexpectedly accepted modified ciphertext")
	}
}
