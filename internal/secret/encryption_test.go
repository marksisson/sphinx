package secret

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestValueDecryptsEncryptedDocumentAndVerifiesMAC(t *testing.T) {
	privateKey, err := os.ReadFile("testdata/private-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile("testdata/encrypted.yaml")
	if err != nil {
		t.Fatal(err)
	}

	decrypter, err := NewDecrypter(strings.TrimSpace(string(privateKey)))
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

func TestEncryptSupportsGuardianKeyAndPassphraseRecovery(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("format: 1\nschema: example/v1\ninscription:\n  owner: platform\nessence:\n  api_key: secret-value\n")
	encrypted, err := Encrypt(plaintext, publicKey, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), "secret-value") || strings.Contains(string(encrypted), "correct horse battery staple") {
		t.Fatal("encrypted relic contains secret material")
	}
	if !strings.Contains(string(encrypted), "owner: platform") || !strings.Contains(string(encrypted), "passphrase-v1") {
		t.Fatal("encrypted relic does not retain protected metadata and recovery envelope")
	}

	decrypter, err := NewDecrypter(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	guardian, err := decrypter.Plain(context.Background(), encrypted)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := DecryptRecovery(encrypted, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if string(guardian) != string(recovery) || !strings.Contains(string(guardian), "api_key: secret-value") {
		t.Fatalf("guardian-key and recovery plaintext differ:\n%s\n%s", guardian, recovery)
	}
	if _, err := DecryptRecovery(encrypted, "wrong passphrase"); err == nil {
		t.Fatal("recovery unexpectedly accepted the wrong passphrase")
	}
	_, otherPublicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(encrypted, otherPublicKey); err == nil {
		t.Fatal("public key validation unexpectedly accepted another guardian public key")
	}
}

func TestValueRejectsModifiedCiphertext(t *testing.T) {
	privateKey, err := os.ReadFile("testdata/private-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile("testdata/encrypted.yaml")
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

	decrypter, err := NewDecrypter(strings.TrimSpace(string(privateKey)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decrypter.Value(context.Background(), modified); err == nil {
		t.Fatal("Value() unexpectedly accepted modified ciphertext")
	}
}
