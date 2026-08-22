package proclamation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

type derivationVector struct {
	Proclamation string `json:"proclamation"`
	Salt         string `json:"salt_base64url"`
	Fingerprint  string `json:"fingerprint"`
	EdPublic     string `json:"ed25519_public_base64url"`
	MLPublic     string `json:"ml_dsa_65_public_base64url"`
}

func TestDeriveKnownAnswerPublicBundle(t *testing.T) {
	data, err := os.ReadFile("../../testdata/interoperability/crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector derivationVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	salt, err := ParseSalt(vector.Salt)
	if err != nil {
		t.Fatal(err)
	}
	credential := NewCredential([]byte(vector.Proclamation))
	defer credential.Destroy()
	derived, err := Derive(credential, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer derived.Destroy()
	if fmt.Sprintf("%v", derived) != "[REDACTED PROCLAMATION DERIVATION]" || fmt.Sprintf("%v", derived.SigningIdentity()) != "[REDACTED HYBRID SIGNING IDENTITY]" {
		t.Fatal("private derivation formatting was not redacted")
	}
	public := derived.Public()
	if public.KDF != KDFSuite || public.Fingerprint != vector.Fingerprint || public.SigningPublic.Ed25519 != vector.EdPublic || public.SigningPublic.MLDSA65 != vector.MLPublic {
		t.Fatal("derived public bundle differs from known-answer vector")
	}
	if derived.AgeIdentity().Recipient().String() != public.AgeRecipient {
		t.Fatal("derived age identity does not match its public recipient")
	}
	if err := ValidatePublic(public); err != nil {
		t.Fatal(err)
	}
	corrupt := public
	corrupt.AgeSuite = "classical"
	if err := ValidatePublic(corrupt); err == nil {
		t.Fatal("ValidatePublic accepted a mixed age suite")
	}
	corrupt = public
	corrupt.SignatureSuite = "ed25519-only"
	if err := ValidatePublic(corrupt); err == nil {
		t.Fatal("ValidatePublic accepted a classical signature suite")
	}
}

func TestGenerateUsesPinnedWordsAndUnbiasedRejection(t *testing.T) {
	samples := make([]byte, 0, 22)
	// 0xffff is outside floor(65536/7776)*7776 and must be rejected.
	samples = append(samples, 0xff, 0xff)
	for index := 0; index < 10; index++ {
		samples = append(samples, 0, byte(index))
	}
	credential, err := Generate(bytes.NewReader(samples))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	if err := credential.WithBytes(func(value []byte) error {
		want := "abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion"
		if string(value) != want {
			t.Fatalf("generated proclamation = %q", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSaltEncodingIsCanonical(t *testing.T) {
	salt, err := GenerateSalt(bytes.NewReader(make([]byte, SaltSize)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSalt(salt.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSalt(base64.URLEncoding.EncodeToString(salt[:])); err == nil {
		t.Fatal("ParseSalt accepted padded base64url")
	}
}

type fakeTerminal struct {
	reads  [][]byte
	writes bytes.Buffer
	calls  int
}

func (f *fakeTerminal) Write(value []byte) (int, error) { return f.writes.Write(value) }
func (f *fakeTerminal) ReadPassword(_ []byte) ([]byte, error) {
	if f.calls >= len(f.reads) {
		return nil, errors.New("no input")
	}
	value := append([]byte(nil), f.reads[f.calls]...)
	f.calls++
	return value, nil
}

func TestGeneratedConfirmationAndThreeAttemptLimit(t *testing.T) {
	phrase := []byte("abacus abdomen abdominal abide abiding ability ablaze able abnormal abrasion")
	source := make([]byte, 20)
	for index := 0; index < 10; index++ {
		source[index*2+1] = byte(index)
	}
	terminal := &fakeTerminal{reads: [][]byte{[]byte("wrong"), phrase}}
	credential, err := GenerateAndConfirm(terminal, bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	credential.Destroy()
	if !bytes.Contains(terminal.writes.Bytes(), phrase) || terminal.calls != 2 {
		t.Fatal("generated proclamation was not displayed and confirmed on the terminal")
	}

	terminal = &fakeTerminal{reads: [][]byte{[]byte("one"), []byte("two"), []byte("three"), phrase}}
	if _, err := PromptVerified(terminal, func(Credential) (bool, error) { return false, nil }); err == nil || terminal.calls != MaximumAttempts {
		t.Fatalf("PromptVerified attempts = %d, error = %v", terminal.calls, err)
	}
}
