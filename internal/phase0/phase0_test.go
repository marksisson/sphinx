package phase0_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	ageVersion   = "v1.3.1"
	sopsVersion  = "v3.12.1"
	circlVersion = "v1.6.1"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "phase0", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPinnedModuleVersions(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for module, version := range map[string]string{
		"filippo.io/age":              ageVersion,
		"github.com/getsops/sops/v3":  sopsVersion,
		"github.com/cloudflare/circl": circlVersion,
	} {
		if !strings.Contains(string(goMod), module+" "+version) {
			t.Errorf("go.mod does not pin %s %s", module, version)
		}
	}
}

func TestWordlistFixture(t *testing.T) {
	wordlist := fixture(t, "eff_large_wordlist.txt")
	digest := sha256.Sum256(wordlist)
	if got, want := hex.EncodeToString(digest[:]), "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"; got != want {
		t.Fatalf("wordlist SHA-256 = %s, want %s", got, want)
	}
	lines := bytes.Split(bytes.TrimSuffix(wordlist, []byte("\n")), []byte("\n"))
	if len(lines) != 7776 {
		t.Fatalf("wordlist has %d entries, want 7776", len(lines))
	}
}

func TestExternalSOPSFixtureDecryptsInProcess(t *testing.T) {
	identity := parseFixtureIdentity(t)
	got := decryptSOPS(t, fixture(t, "artifact.sops.yaml"), identity)
	assertYAMLEqual(t, got, fixture(t, "artifact.plain.yaml"))
}

func TestNativeAgeAndSOPSExternalInteroperability(t *testing.T) {
	ageBin, sopsBin := os.Getenv("SPHINX_TEST_AGE_BIN"), os.Getenv("SPHINX_TEST_SOPS_BIN")
	if ageBin == "" || sopsBin == "" {
		t.Skip("set SPHINX_TEST_AGE_BIN and SPHINX_TEST_SOPS_BIN to exact pinned tools")
	}
	assertToolVersion(t, ageBin, "v1.3.1")
	assertToolVersion(t, sopsBin, "sops 3.12.1")

	identity := parseFixtureIdentity(t)
	recipient := identity.Recipient().String()

	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "in-process-to-age-cli"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join("..", "..", "testdata", "phase0", "hybrid-identity.txt")
	cmd := exec.Command(ageBin, "--decrypt", "--identity", identityPath)
	cmd.Stdin = bytes.NewReader(encrypted.Bytes())
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "in-process-to-age-cli" {
		t.Fatalf("age CLI decrypt: %v: %s", err, out)
	}

	cmd = exec.Command(ageBin, "--encrypt", "--recipient", recipient)
	cmd.Stdin = strings.NewReader("age-cli-to-in-process")
	externalCiphertext, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(externalCiphertext), identity)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil || string(out) != "age-cli-to-in-process" {
		t.Fatalf("in-process age decrypt: %v: %q", err, out)
	}

	inProcessSOPS := encryptSOPS(t, fixture(t, "artifact.plain.yaml"), recipient)
	cmd = exec.Command(sopsBin, "--decrypt", "--input-type", "yaml", "--output-type", "yaml", "/dev/stdin")
	cmd.Stdin = bytes.NewReader(inProcessSOPS)
	cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+identity.String())
	externalPlain, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("SOPS CLI decrypt: %v: %s", err, externalPlain)
	}
	assertYAMLEqual(t, externalPlain, fixture(t, "artifact.plain.yaml"))
}

func parseFixtureIdentity(t *testing.T) *age.HybridIdentity {
	t.Helper()
	identities, err := age.ParseIdentities(bytes.NewReader(fixture(t, "hybrid-identity.txt")))
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 {
		t.Fatalf("fixture has %d identities, want 1", len(identities))
	}
	identity, ok := identities[0].(*age.HybridIdentity)
	if !ok {
		t.Fatalf("fixture identity type is %T, want *age.HybridIdentity", identities[0])
	}
	want := strings.TrimSpace(string(fixture(t, "hybrid-recipient.txt")))
	if got := identity.Recipient().String(); got != want {
		t.Fatal("fixture identity and recipient do not match")
	}
	return identity
}

func encryptSOPS(t *testing.T, plaintext []byte, recipient string) []byte {
	t.Helper()
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	masterKey, err := sopsage.MasterKeyFromRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	dataKey := bytes.Repeat([]byte{0x42}, 32)
	if err := masterKey.Encrypt(dataKey); err != nil {
		t.Fatal(err)
	}
	tree := sops.Tree{Branches: branches, Metadata: sops.Metadata{
		EncryptedRegex: "^secrets$",
		Version:        "3.12.1",
		KeyGroups:      []sops.KeyGroup{{masterKey}},
	}}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		t.Fatal(err)
	}
	tree.Metadata.LastModified = time.Unix(1_700_000_000, 0).UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decryptSOPS(t *testing.T, encrypted []byte, identity *age.HybridIdentity) []byte {
	t.Helper()
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Metadata.EncryptedRegex != "^secrets$" || tree.Metadata.Version != "3.12.1" {
		t.Fatalf("unexpected SOPS metadata selector/version: %q/%q", tree.Metadata.EncryptedRegex, tree.Metadata.Version)
	}
	if len(tree.Metadata.KeyGroups) != 1 || len(tree.Metadata.KeyGroups[0]) != 1 {
		t.Fatal("fixture must have exactly one independent age recipient")
	}
	masterKey, ok := tree.Metadata.KeyGroups[0][0].(*sopsage.MasterKey)
	if !ok || masterKey.Recipient != identity.Recipient().String() {
		t.Fatal("fixture recipient is not the expected native hybrid recipient")
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(masterKey.EncryptedKey)), identity)
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := io.ReadAll(r)
	if err != nil || len(dataKey) != 32 {
		t.Fatalf("decrypt SOPS data key: %v (length %d)", err, len(dataKey))
	}
	defer clear(dataKey)
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		t.Fatal(err)
	}
	original, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	originalString, ok := original.(string)
	if !ok || subtle.ConstantTimeCompare([]byte(originalString), []byte(mac)) != 1 {
		t.Fatal("SOPS MAC mismatch")
	}
	out, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertYAMLEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue, wantValue any
	if err := yaml.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("parse got YAML: %v\n%s", err, got)
	}
	if err := yaml.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("parse wanted YAML: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("YAML differs\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func assertToolVersion(t *testing.T, binary, want string) {
	t.Helper()
	out, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), want) {
		t.Fatalf("%s version: %v: %s; want %q", binary, err, out, want)
	}
}

type cryptoVector struct {
	Proclamation   string `json:"proclamation"`
	Salt           string `json:"salt_base64url"`
	Root           string `json:"argon2id_root_base64url"`
	AgeSeed        string `json:"age_seed_base64url"`
	EdSeed         string `json:"ed25519_seed_base64url"`
	MLSeed         string `json:"ml_dsa_65_seed_base64url"`
	TombID         string `json:"tomb_id"`
	Purpose        string `json:"purpose"`
	Manifest       string `json:"manifest_utf8"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Payload        string `json:"payload_utf8"`
	Frame          string `json:"signature_frame_base64url"`
	EdPublic       string `json:"ed25519_public_base64url"`
	MLPublic       string `json:"ml_dsa_65_public_base64url"`
	Fingerprint    string `json:"fingerprint"`
	EdSignature    string `json:"ed25519_signature_base64url"`
	MLSignature    string `json:"ml_dsa_65_signature_base64url"`
}

func TestProclamationAndSignatureKnownAnswerVector(t *testing.T) {
	var v cryptoVector
	if err := json.Unmarshal(fixture(t, "crypto-vectors.json"), &v); err != nil {
		t.Fatal(err)
	}
	salt := decode64(t, v.Salt)
	root := argon2.IDKey([]byte(v.Proclamation), salt, 3, 262144, 4, 32)
	assertBytes(t, "Argon2id root", root, decode64(t, v.Root))
	ageSeed := derive(root, "sphinx/proclamation/age/mlkem768x25519")
	edSeed := derive(root, "sphinx/proclamation/sign/ed25519")
	mlSeedBytes := derive(root, "sphinx/proclamation/sign/ml-dsa-65")
	assertBytes(t, "age seed", ageSeed, decode64(t, v.AgeSeed))
	assertBytes(t, "Ed25519 seed", edSeed, decode64(t, v.EdSeed))
	assertBytes(t, "ML-DSA-65 seed", mlSeedBytes, decode64(t, v.MLSeed))

	frame := signatureFrame(v.Purpose, v.TombID, []byte(v.Manifest), []byte(v.Payload))
	assertBytes(t, "signature frame", frame, decode64(t, v.Frame))
	manifestDigest := sha256.Sum256([]byte(v.Manifest))
	if got := hex.EncodeToString(manifestDigest[:]); got != v.ManifestSHA256 {
		t.Fatalf("manifest digest = %s, want %s", got, v.ManifestSHA256)
	}

	edPrivate := ed25519.NewKeyFromSeed(edSeed)
	edPublic := edPrivate.Public().(ed25519.PublicKey)
	assertBytes(t, "Ed25519 public key", edPublic, decode64(t, v.EdPublic))
	edSignature := ed25519.Sign(edPrivate, frame)
	assertBytes(t, "Ed25519 signature", edSignature, decode64(t, v.EdSignature))
	if !ed25519.Verify(edPublic, frame, edSignature) {
		t.Fatal("Ed25519 vector does not verify")
	}

	var mlSeed [mldsa65.SeedSize]byte
	copy(mlSeed[:], mlSeedBytes)
	mlPublic, mlPrivate := mldsa65.NewKeyFromSeed(&mlSeed)
	assertBytes(t, "ML-DSA-65 public key", mlPublic.Bytes(), decode64(t, v.MLPublic))
	mlSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mlPrivate, frame, nil, false, mlSignature); err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "ML-DSA-65 signature", mlSignature, decode64(t, v.MLSignature))
	if !mldsa65.Verify(mlPublic, frame, nil, mlSignature) {
		t.Fatal("ML-DSA-65 vector does not verify")
	}

	fingerprintInput := append(lengthPrefix([]byte("ed25519+mldsa65-v1")), lengthPrefix(edPublic)...)
	fingerprintInput = append(fingerprintInput, lengthPrefix(mlPublic.Bytes())...)
	fingerprint := sha256.Sum256(fingerprintInput)
	if got := "SHA256:" + base64.RawURLEncoding.EncodeToString(fingerprint[:]); got != v.Fingerprint {
		t.Fatalf("fingerprint = %s, want %s", got, v.Fingerprint)
	}
}

func derive(root []byte, label string) []byte {
	reader := hkdf.New(func() hash.Hash { return sha256.New() }, root, nil, []byte(label))
	out := make([]byte, 32)
	if _, err := io.ReadFull(reader, out); err != nil {
		panic(err)
	}
	return out
}

func signatureFrame(purpose, tombID string, manifest, payload []byte) []byte {
	digest := sha256.Sum256(manifest)
	out := []byte("sphinx-signature-v1")
	for _, field := range [][]byte{[]byte(purpose), []byte(tombID), digest[:], payload} {
		out = append(out, lengthPrefix(field)...)
	}
	return out
}

func lengthPrefix(value []byte) []byte {
	out := make([]byte, 8+len(value))
	binary.BigEndian.PutUint64(out, uint64(len(value)))
	copy(out[8:], value)
	return out
}

func decode64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\ngot:  %s\nwant: %s", name, base64.RawURLEncoding.EncodeToString(got), base64.RawURLEncoding.EncodeToString(want))
	}
}

func TestFixtureChecksums(t *testing.T) {
	checksums := map[string]string{
		"artifact.plain.yaml":    "53e3ff1fe5e590c97ed375b5ca73fe95028a37dcb92c466286760df24f9d421f",
		"artifact.sops.yaml":     "281c05f38edfb2e16c969ba91f785525f17297bdfecf3599397dee62682f714d",
		"crypto-vectors.json":    "29292850e9ffee3d214723d7eb3c9fcfbcbd94d07da5a5c64d15e6184cf45381",
		"eff_large_wordlist.txt": "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e",
		"hybrid-identity.txt":    "8540d88ba5e0aefec499580f9355900d2b9d8eb01ba3218bd7633dced926b278",
		"hybrid-recipient.txt":   "c76002b0410f1fad4b12a7b275c3cf2c99240a0fcbb064a3163da42a546efd67",
	}
	for name, want := range checksums {
		digest := sha256.Sum256(fixture(t, name))
		if got := fmt.Sprintf("%x", digest); got != want {
			t.Errorf("%s SHA-256 = %s, want %s", name, got, want)
		}
	}
}
