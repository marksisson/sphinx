package proclamation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/hybridage"
	"github.com/marksisson/sphinx/internal/hybridsign"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	KDFSuite = "argon2id-v1"
	SaltSize = 32
)

type Salt [SaltSize]byte

type SigningPublic struct {
	Ed25519 string
	MLDSA65 string
}

type PublicBundle struct {
	KDF            string
	Salt           string
	AgeSuite       string
	AgeRecipient   string
	SignatureSuite string
	SigningPublic  SigningPublic
	Fingerprint    string
}

type Derived struct {
	ageIdentity *age.HybridIdentity
	signing     *hybridsign.PrivateBundle
	public      PublicBundle
}

func GenerateSalt(source io.Reader) (Salt, error) {
	if source == nil {
		source = rand.Reader
	}
	var salt Salt
	if _, err := io.ReadFull(source, salt[:]); err != nil {
		return Salt{}, fmt.Errorf("generate proclamation salt: %w", err)
	}
	return salt, nil
}

func ParseSalt(value string) (Salt, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != SaltSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return Salt{}, fmt.Errorf("proclamation salt must be canonical unpadded base64url of 32 bytes")
	}
	var salt Salt
	copy(salt[:], decoded)
	clear(decoded)
	return salt, nil
}

func (s Salt) String() string { return base64.RawURLEncoding.EncodeToString(s[:]) }

// Derive applies the immutable argon2id-v1 profile and derives three
// independent suite seeds with nil-salt HKDF-SHA-256.
func Derive(credential Credential, salt Salt) (*Derived, error) {
	var result *Derived
	err := credential.WithBytes(func(proclamation []byte) error {
		if err := validatePhrase(proclamation); err != nil {
			return err
		}
		root := argon2.IDKey(proclamation, salt[:], 3, 262144, 4, 32)
		defer clear(root)
		ageSeed, err := deriveSeed(root, "sphinx/proclamation/age/mlkem768x25519")
		if err != nil {
			return err
		}
		defer clear(ageSeed)
		edSeed, err := deriveSeed(root, "sphinx/proclamation/sign/ed25519")
		if err != nil {
			return err
		}
		defer clear(edSeed)
		mlSeed, err := deriveSeed(root, "sphinx/proclamation/sign/ml-dsa-65")
		if err != nil {
			return err
		}
		defer clear(mlSeed)

		ageIdentity, err := hybridage.IdentityFromSeed(ageSeed)
		if err != nil {
			return err
		}
		signing, err := hybridsign.NewPrivate(edSeed, mlSeed)
		if err != nil {
			return err
		}
		public := signing.Public()
		edPublic, mlPublic := public.Encoded()
		fingerprint, err := public.Fingerprint()
		if err != nil {
			signing.Destroy()
			return err
		}
		ageRecipient := hybridage.Recipient(ageIdentity)
		result = &Derived{ageIdentity: ageIdentity, signing: signing, public: PublicBundle{
			KDF: KDFSuite, Salt: salt.String(), AgeSuite: hybridage.Suite,
			AgeRecipient: ageRecipient, SignatureSuite: hybridsign.Suite,
			SigningPublic: SigningPublic{Ed25519: edPublic, MLDSA65: mlPublic},
			Fingerprint:   fingerprint,
		}}
		return nil
	})
	return result, err
}

func ValidatePublic(bundle PublicBundle) error {
	if bundle.KDF != KDFSuite {
		return fmt.Errorf("proclamation KDF suite %q is unsupported", bundle.KDF)
	}
	if _, err := ParseSalt(bundle.Salt); err != nil {
		return err
	}
	if bundle.AgeSuite != hybridage.Suite {
		return fmt.Errorf("proclamation age suite %q is unsupported", bundle.AgeSuite)
	}
	if _, err := hybridage.ParseRecipient(bundle.AgeRecipient); err != nil {
		return err
	}
	if bundle.SignatureSuite != hybridsign.Suite {
		return fmt.Errorf("proclamation signature suite %q is unsupported", bundle.SignatureSuite)
	}
	if _, err := hybridsign.ParsePublicBundle(bundle.SigningPublic.Ed25519, bundle.SigningPublic.MLDSA65, bundle.Fingerprint); err != nil {
		return err
	}
	return nil
}

func (*Derived) String() string   { return "[REDACTED PROCLAMATION DERIVATION]" }
func (*Derived) GoString() string { return "[REDACTED PROCLAMATION DERIVATION]" }

func (d *Derived) AgeIdentity() *age.HybridIdentity           { return d.ageIdentity }
func (d *Derived) SigningIdentity() *hybridsign.PrivateBundle { return d.signing }
func (d *Derived) Public() PublicBundle                       { return d.public }

func (d *Derived) Destroy() {
	if d == nil {
		return
	}
	if d.signing != nil {
		d.signing.Destroy()
	}
	d.signing = nil
	d.ageIdentity = nil
	d.public = PublicBundle{}
}

func deriveSeed(root []byte, label string) ([]byte, error) {
	reader := hkdf.New(func() hash.Hash { return sha256.New() }, root, nil, []byte(label))
	seed := make([]byte, 32)
	if _, err := io.ReadFull(reader, seed); err != nil {
		return nil, fmt.Errorf("derive proclamation key seed: %w", err)
	}
	return seed, nil
}
