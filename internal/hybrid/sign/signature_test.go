package sign

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	EdSeed      string `json:"ed25519_seed_base64url"`
	MLSeed      string `json:"ml_dsa_65_seed_base64url"`
	EdPublic    string `json:"ed25519_public_base64url"`
	MLPublic    string `json:"ml_dsa_65_public_base64url"`
	Fingerprint string `json:"fingerprint"`
	EdSignature string `json:"ed25519_signature_base64url"`
	MLSignature string `json:"ml_dsa_65_signature_base64url"`
	TombID      string `json:"tomb_id"`
	Purpose     string `json:"purpose"`
	Manifest    string `json:"manifest_utf8"`
	Payload     string `json:"payload_utf8"`
	Frame       string `json:"signature_frame_base64url"`
}

func TestKnownAnswerAndBothRequiredVerification(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/interoperability/crypto-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	private, err := NewPrivate(decode(t, v.EdSeed), decode(t, v.MLSeed))
	if err != nil {
		t.Fatal(err)
	}
	defer private.Destroy()
	public := private.Public()
	edPublic, mlPublic := public.Encoded()
	if edPublic != v.EdPublic || mlPublic != v.MLPublic {
		t.Fatal("derived public bundle differs from known-answer vector")
	}
	fingerprint, err := public.Fingerprint()
	if err != nil || fingerprint != v.Fingerprint {
		t.Fatalf("fingerprint = %q, %v", fingerprint, err)
	}
	if _, err := ParsePublicBundle(edPublic, mlPublic, fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicBundle(edPublic, mlPublic, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("ParsePublicBundle accepted a mismatched fingerprint")
	}
	digest := sha256.Sum256([]byte(v.Manifest))
	frame, err := Frame(DecreePurpose, v.TombID, digest[:], []byte(v.Payload))
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(frame) != v.Frame {
		t.Fatal("signature frame differs from known-answer vector")
	}
	signature, err := private.Sign(DecreePurpose, v.TombID, digest[:], []byte(v.Payload))
	if err != nil {
		t.Fatal(err)
	}
	edSignature, mlSignature := signature.Encoded()
	if edSignature != v.EdSignature || mlSignature != v.MLSignature {
		t.Fatal("deterministic signature differs from known-answer vector")
	}
	if err := public.Verify(DecreePurpose, v.TombID, digest[:], []byte(v.Payload), signature); err != nil {
		t.Fatal(err)
	}
	repeated, err := private.Sign(DecreePurpose, v.TombID, digest[:], []byte(v.Payload))
	if err != nil {
		t.Fatal(err)
	}
	repeatedEd, repeatedML := repeated.Encoded()
	if repeatedEd != edSignature || repeatedML != mlSignature {
		t.Fatal("hybrid signature is not deterministic")
	}
	if err := public.Verify(DecreePurpose, v.TombID, digest[:], []byte(v.Payload+"x"), signature); err == nil {
		t.Fatal("verification accepted a different payload")
	}

	badEd, _ := ParseSignature(v.EdSignature, v.MLSignature)
	badEd.ed[0] ^= 1
	if err := public.Verify(DecreePurpose, v.TombID, digest[:], []byte(v.Payload), badEd); err == nil {
		t.Fatal("verification accepted a corrupt Ed25519 component")
	}
	badML, _ := ParseSignature(v.EdSignature, v.MLSignature)
	badML.ml[0] ^= 1
	if err := public.Verify(DecreePurpose, v.TombID, digest[:], []byte(v.Payload), badML); err == nil {
		t.Fatal("verification accepted a corrupt ML-DSA-65 component")
	}
}

func TestStrictEncodingsAndFrameDomains(t *testing.T) {
	if _, err := ParsePublic(base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 1952))); err == nil {
		t.Fatal("ParsePublic accepted a short component")
	}
	id := "123e4567-e89b-42d3-a456-426614174000"
	if _, err := Frame(DecreePurpose, id, nil, nil); err == nil {
		t.Fatal("decree frame accepted a missing manifest digest")
	}
	if _, err := Frame(RotationFromPurpose, id, make([]byte, 32), nil); err == nil {
		t.Fatal("rotation frame accepted a manifest digest")
	}
	if _, err := Frame(Purpose("other"), id, nil, nil); err == nil {
		t.Fatal("frame accepted an unsupported purpose")
	}
	if _, err := Frame(RotationToPurpose, "123E4567-E89B-42D3-A456-426614174000", nil, nil); err == nil {
		t.Fatal("frame accepted a noncanonical tomb ID")
	}
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
