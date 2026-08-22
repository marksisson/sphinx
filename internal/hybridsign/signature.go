// Package hybridsign implements the fixed Ed25519 + ML-DSA-65 signature
// suite. Both components always sign and verify one domain-separated frame.
package hybridsign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const Suite = "ed25519+mldsa65-v1"

type Purpose string

const (
	DecreePurpose       Purpose = "sphinx decree"
	RotationFromPurpose Purpose = "sphinx proclamation rotation/from"
	RotationToPurpose   Purpose = "sphinx proclamation rotation/to"
)

var tombIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type PublicBundle struct {
	ed []byte
	ml []byte
}

type PrivateBundle struct {
	ed ed25519.PrivateKey
	ml *mldsa65.PrivateKey
}

type Signature struct {
	ed []byte
	ml []byte
}

func NewPrivate(edSeed, mlSeed []byte) (*PrivateBundle, error) {
	if len(edSeed) != ed25519.SeedSize || len(mlSeed) != mldsa65.SeedSize {
		return nil, fmt.Errorf("hybrid signing seeds must each be exactly 32 bytes")
	}
	edPrivate := ed25519.NewKeyFromSeed(edSeed)
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], mlSeed)
	_, mlPrivate := mldsa65.NewKeyFromSeed(&seed)
	clear(seed[:])
	return &PrivateBundle{ed: edPrivate, ml: mlPrivate}, nil
}

func (*PrivateBundle) String() string   { return "[REDACTED HYBRID SIGNING IDENTITY]" }
func (*PrivateBundle) GoString() string { return "[REDACTED HYBRID SIGNING IDENTITY]" }

func (p *PrivateBundle) Public() PublicBundle {
	return PublicBundle{
		ed: append([]byte(nil), p.ed.Public().(ed25519.PublicKey)...),
		ml: append([]byte(nil), p.ml.Public().(*mldsa65.PublicKey).Bytes()...),
	}
}

func (p *PrivateBundle) Sign(purpose Purpose, tombID string, manifestDigest, payload []byte) (Signature, error) {
	frame, err := Frame(purpose, tombID, manifestDigest, payload)
	if err != nil {
		return Signature{}, err
	}
	return p.signFrame(frame)
}

func (p *PrivateBundle) signFrame(frame []byte) (Signature, error) {
	if p == nil || len(p.ed) != ed25519.PrivateKeySize || p.ml == nil {
		return Signature{}, fmt.Errorf("hybrid signing private bundle is unavailable")
	}
	edSignature := ed25519.Sign(p.ed, frame)
	mlSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(p.ml, frame, nil, false, mlSignature); err != nil {
		clear(edSignature)
		return Signature{}, fmt.Errorf("sign ML-DSA-65 component: %w", err)
	}
	return Signature{ed: edSignature, ml: mlSignature}, nil
}

func (p *PrivateBundle) Destroy() {
	if p == nil {
		return
	}
	clear(p.ed)
	p.ed = nil
	if p.ml != nil {
		*p.ml = mldsa65.PrivateKey{}
		p.ml = nil
	}
}

func ParsePublic(edEncoded, mlEncoded string) (PublicBundle, error) {
	ed, err := decodeCanonical(edEncoded, ed25519.PublicKeySize, "Ed25519 public key")
	if err != nil {
		return PublicBundle{}, err
	}
	ml, err := decodeCanonical(mlEncoded, mldsa65.PublicKeySize, "ML-DSA-65 public key")
	if err != nil {
		clear(ed)
		return PublicBundle{}, err
	}
	return PublicBundle{ed: ed, ml: ml}, nil
}

func ParsePublicBundle(edEncoded, mlEncoded, fingerprint string) (PublicBundle, error) {
	public, err := ParsePublic(edEncoded, mlEncoded)
	if err != nil {
		return PublicBundle{}, err
	}
	derived, err := public.Fingerprint()
	if err != nil {
		return PublicBundle{}, err
	}
	if fingerprint != derived {
		return PublicBundle{}, fmt.Errorf("hybrid signing public-bundle fingerprint does not match its keys")
	}
	return public, nil
}

func ParseSignature(edEncoded, mlEncoded string) (Signature, error) {
	ed, err := decodeCanonical(edEncoded, ed25519.SignatureSize, "Ed25519 signature")
	if err != nil {
		return Signature{}, err
	}
	ml, err := decodeCanonical(mlEncoded, mldsa65.SignatureSize, "ML-DSA-65 signature")
	if err != nil {
		clear(ed)
		return Signature{}, err
	}
	return Signature{ed: ed, ml: ml}, nil
}

func (p PublicBundle) Encoded() (ed25519Value, mlDSA65Value string) {
	return base64.RawURLEncoding.EncodeToString(p.ed), base64.RawURLEncoding.EncodeToString(p.ml)
}

func (s Signature) Encoded() (ed25519Value, mlDSA65Value string) {
	return base64.RawURLEncoding.EncodeToString(s.ed), base64.RawURLEncoding.EncodeToString(s.ml)
}

func (p PublicBundle) Fingerprint() (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	input := append(lengthPrefix([]byte(Suite)), lengthPrefix(p.ed)...)
	input = append(input, lengthPrefix(p.ml)...)
	digest := sha256.Sum256(input)
	clear(input)
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (p PublicBundle) Verify(purpose Purpose, tombID string, manifestDigest, payload []byte, signature Signature) error {
	frame, err := Frame(purpose, tombID, manifestDigest, payload)
	if err != nil {
		return err
	}
	return p.verifyFrame(frame, signature)
}

func (p PublicBundle) verifyFrame(frame []byte, signature Signature) error {
	if err := p.validate(); err != nil {
		return err
	}
	if len(signature.ed) != ed25519.SignatureSize || len(signature.ml) != mldsa65.SignatureSize {
		return fmt.Errorf("both exact-width hybrid signature components are required")
	}
	if !ed25519.Verify(ed25519.PublicKey(p.ed), frame, signature.ed) {
		return fmt.Errorf("Ed25519 signature component is invalid")
	}
	var mlPublic mldsa65.PublicKey
	if err := mlPublic.UnmarshalBinary(p.ml); err != nil {
		return fmt.Errorf("decode ML-DSA-65 public key: %w", err)
	}
	if !mldsa65.Verify(&mlPublic, frame, nil, signature.ml) {
		return fmt.Errorf("ML-DSA-65 signature component is invalid")
	}
	return nil
}

func (p PublicBundle) validate() error {
	if len(p.ed) != ed25519.PublicKeySize || len(p.ml) != mldsa65.PublicKeySize {
		return fmt.Errorf("both exact-width hybrid public-key components are required")
	}
	var mlPublic mldsa65.PublicKey
	if err := mlPublic.UnmarshalBinary(p.ml); err != nil {
		return fmt.Errorf("decode ML-DSA-65 public key: %w", err)
	}
	return nil
}

// Frame creates the exact version-1 binary frame. Decree signatures require a
// 32-byte manifest digest; transition signatures require no manifest digest.
func Frame(purpose Purpose, tombID string, manifestDigest, payload []byte) ([]byte, error) {
	if !tombIDPattern.MatchString(tombID) {
		return nil, fmt.Errorf("tomb ID must be a lowercase UUIDv4")
	}
	switch purpose {
	case DecreePurpose:
		if len(manifestDigest) != sha256.Size {
			return nil, fmt.Errorf("decree signature frame requires a 32-byte manifest digest")
		}
	case RotationFromPurpose, RotationToPurpose:
		if len(manifestDigest) != 0 {
			return nil, fmt.Errorf("rotation signature frame forbids a manifest digest")
		}
	default:
		return nil, fmt.Errorf("signature purpose %q is unsupported", purpose)
	}
	frame := []byte("sphinx-signature-v1")
	for _, field := range [][]byte{[]byte(purpose), []byte(tombID), manifestDigest, payload} {
		frame = append(frame, lengthPrefix(field)...)
	}
	return frame, nil
}

func lengthPrefix(value []byte) []byte {
	encoded := make([]byte, 8+len(value))
	binary.BigEndian.PutUint64(encoded, uint64(len(value)))
	copy(encoded[8:], value)
	return encoded
}

func decodeCanonical(value string, size int, name string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url with exact width", name)
	}
	return decoded, nil
}
