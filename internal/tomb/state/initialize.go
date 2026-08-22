package state

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/marksisson/sphinx/internal/decree"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/proclamation"
)

type InitialState struct {
	Manifest, Decree, Signature []byte
	TombID                      string
}

func Initialize(schemas map[string]gitresource.Blob, derived *proclamation.Derived, source io.Reader) (InitialState, error) {
	if len(schemas) == 0 {
		return InitialState{}, fmt.Errorf("decree initialization requires at least one schema")
	}
	if derived == nil {
		return InitialState{}, fmt.Errorf("generated proclamation derivation is required")
	}
	if source == nil {
		source = rand.Reader
	}
	raw := make([]byte, 16)
	if _, err := io.ReadFull(source, raw); err != nil {
		return InitialState{}, fmt.Errorf("generate tomb ID: %w", err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	tombID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	clear(raw)
	public := derived.Public()
	manifest := Manifest{Version: Version, TombID: tombID, Proclamation: Proclamation{KDF: public.KDF, Salt: public.Salt, AgeSuite: public.AgeSuite, AgeRecipient: public.AgeRecipient, SignatureSuite: public.SignatureSuite, PublicKey: PublicKey{Ed25519: public.SigningPublic.Ed25519, MLDSA65: public.SigningPublic.MLDSA65}, Fingerprint: public.Fingerprint}}
	manifestBytes, err := EncodeManifest(manifest)
	if err != nil {
		return InitialState{}, err
	}
	artifactLocks, schemaLocks := Locks(map[string]gitresource.Blob{}, schemas)
	document := decree.Document{Version: decree.Version, Generation: 1, ArtifactLocks: artifactLocks, SchemaLocks: schemaLocks, Rules: []decree.Rule{}}
	decreeBytes, err := decree.Encode(document)
	if err != nil {
		return InitialState{}, err
	}
	signature, err := EncodeDecreeSignature(manifestBytes, decreeBytes, manifest, derived.SigningIdentity())
	if err != nil {
		return InitialState{}, err
	}
	return InitialState{Manifest: manifestBytes, Decree: decreeBytes, Signature: signature, TombID: tombID}, nil
}
