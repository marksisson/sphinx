// Package hybridage is the only production boundary for age recipients and
// identities. It accepts exactly age v1.3.1's native ML-KEM-768 + X25519
// hybrid suite and never invokes plugins or external programs.
package hybridage

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"filippo.io/age"
	sopsage "github.com/getsops/sops/v3/age"
)

const Suite = "mlkem768x25519-v1"

func IdentityFromSeed(seed []byte) (*age.HybridIdentity, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("native hybrid identity seed must be exactly 32 bytes")
	}
	encoded := bech32Encode("AGE-SECRET-KEY-PQ-", seed)
	identity, err := age.ParseHybridIdentity(encoded)
	if err != nil {
		return nil, fmt.Errorf("derive native hybrid identity: %w", err)
	}
	return identity, nil
}

func Generate() (*age.HybridIdentity, error) {
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate hybrid guardian identity: %w", err)
	}
	return identity, nil
}

func ParseIdentity(value string) (*age.HybridIdentity, error) {
	if strings.TrimSpace(value) != value || !strings.HasPrefix(value, "AGE-SECRET-KEY-PQ-1") {
		return nil, fmt.Errorf("identity is not a canonical native hybrid identity")
	}
	identity, err := age.ParseHybridIdentity(value)
	if err != nil || identity.String() != value {
		return nil, fmt.Errorf("identity is not a canonical native hybrid identity")
	}
	return identity, nil
}

func ParseRecipient(value string) (*age.HybridRecipient, error) {
	if strings.TrimSpace(value) != value || !strings.HasPrefix(value, "age1pq1") {
		return nil, fmt.Errorf("recipient is not a canonical native hybrid recipient")
	}
	recipient, err := age.ParseHybridRecipient(value)
	if err != nil || recipient.String() != value {
		return nil, fmt.Errorf("recipient is not a canonical native hybrid recipient")
	}
	return recipient, nil
}

func Recipient(identity *age.HybridIdentity) string { return identity.Recipient().String() }

func Fingerprint(recipient string) (string, error) {
	parsed, err := ParseRecipient(recipient)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(parsed.String()))
	return "SHA256:" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// MasterKey constructs SOPS' native age master key only after the recipient
// has passed the stricter hybrid-suite boundary.
func MasterKey(recipient string) (*sopsage.MasterKey, error) {
	parsed, err := ParseRecipient(recipient)
	if err != nil {
		return nil, err
	}
	key, err := sopsage.MasterKeyFromRecipient(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("construct native hybrid SOPS master key: %w", err)
	}
	return key, nil
}

// ApplyIdentity injects one already parsed native hybrid identity directly
// into a SOPS age master key. No identity file or environment lookup occurs.
func ApplyIdentity(key *sopsage.MasterKey, identity *age.HybridIdentity) error {
	if key == nil || identity == nil {
		return fmt.Errorf("hybrid SOPS key and identity are required")
	}
	if _, err := ParseRecipient(key.Recipient); err != nil {
		return fmt.Errorf("SOPS master key recipient: %w", err)
	}
	if _, err := ParseIdentity(identity.String()); err != nil {
		return err
	}
	identities := sopsage.ParsedIdentities{identity}
	identities.ApplyToMasterKey(key)
	return nil
}

// bech32Encode is the BIP173 encoder used by age's native identity format.
// Keeping only the encoder here avoids exposing or inventing key material.
func bech32Encode(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	values := convertBits(data)
	expanded := make([]byte, 0, len(hrp)*2+1+len(values)+6)
	lower := strings.ToLower(hrp)
	for _, value := range []byte(lower) {
		expanded = append(expanded, value>>5)
	}
	expanded = append(expanded, 0)
	for _, value := range []byte(lower) {
		expanded = append(expanded, value&31)
	}
	checksumInput := append(expanded, values...)
	checksumInput = append(checksumInput, 0, 0, 0, 0, 0, 0)
	checksum := polymod(checksumInput) ^ 1
	var out strings.Builder
	out.WriteString(lower)
	out.WriteByte('1')
	for _, value := range values {
		out.WriteByte(charset[value])
	}
	for index := 0; index < 6; index++ {
		out.WriteByte(charset[byte(checksum>>uint(5*(5-index)))&31])
	}
	return strings.ToUpper(out.String())
}

func convertBits(data []byte) []byte {
	out := make([]byte, 0, (len(data)*8+4)/5)
	var accumulator uint32
	var bits uint
	for _, value := range data {
		accumulator = accumulator<<8 | uint32(value)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(accumulator>>bits)&31)
		}
	}
	if bits > 0 {
		out = append(out, byte(accumulator<<(5-bits))&31)
	}
	return out
}

func polymod(values []byte) uint32 {
	generators := [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for index, generator := range generators {
			if top>>index&1 == 1 {
				checksum ^= generator
			}
		}
	}
	return checksum
}
