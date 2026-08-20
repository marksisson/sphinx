package secret

import (
	"context"
	"os"
	"strings"
	"testing"
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
