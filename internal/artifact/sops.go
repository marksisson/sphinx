package artifact

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
	"github.com/marksisson/sphinx/internal/hybridage"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/yamlstrict"
)

const (
	EncryptedRegex               = "^secrets$"
	SOPSVersion                  = "3.12.1"
	UnverifiedInscriptionWarning = "UNVERIFIED: inscriptions have not been verified through the SOPS MAC and MUST NOT be trusted as authenticated artifact content."
	UnverifiedInscriptionCode    = "unverified_inscriptions"
)

var encryptedValuePattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:[^,]+,iv:[^,]+,tag:[^,]+,type:(?:str|int|bool)\]$`)

type Engine struct {
	Random io.Reader
	Now    func() time.Time
}

type Inspection struct {
	Format                int
	Schema                string
	Inscriptions          map[string]any
	Recipients            []string
	RecipientFingerprints []string
	Verified              bool
	WarningCode           string
	Warning               string
}

type encryptedWire struct {
	Format       int            `yaml:"format"`
	Schema       string         `yaml:"schema"`
	Inscriptions map[string]any `yaml:"inscriptions"`
	Secrets      map[string]any `yaml:"secrets"`
	SOPS         metadataWire   `yaml:"sops"`
}

type metadataWire struct {
	Age            []ageWire `yaml:"age"`
	LastModified   string    `yaml:"lastmodified"`
	MAC            string    `yaml:"mac"`
	EncryptedRegex string    `yaml:"encrypted_regex"`
	Version        string    `yaml:"version"`
}

type ageWire struct {
	Recipient string `yaml:"recipient"`
	Enc       string `yaml:"enc"`
}

// Create encrypts a schema-valid document for exactly the proclamation
// recipient. Guardian recipients are added only by an explicit later mutation.
func (e Engine) Create(document Document, definition schema.Definition, proclamationRecipient string) ([]byte, error) {
	return e.encrypt(document, definition, proclamationRecipient, nil)
}

// Inspect returns only repository-visible fields. It deliberately performs no
// decryption and marks every inscription as unauthenticated.
func (e Engine) Inspect(encrypted []byte, proclamationRecipient string) (Inspection, error) {
	wire, _, recipients, err := parseEncrypted(encrypted, proclamationRecipient)
	if err != nil {
		return Inspection{}, err
	}
	fingerprints := make([]string, len(recipients))
	for index, recipient := range recipients {
		fingerprints[index], err = hybridage.Fingerprint(recipient)
		if err != nil {
			return Inspection{}, err
		}
	}
	return Inspection{Format: wire.Format, Schema: wire.Schema, Inscriptions: cloneValues(wire.Inscriptions), Recipients: append([]string(nil), recipients...), RecipientFingerprints: fingerprints, Verified: false, WarningCode: UnverifiedInscriptionCode, Warning: UnverifiedInscriptionWarning}, nil
}

// DecryptWithIdentities tries identities in caller-supplied order. Every
// identity and every artifact recipient must already satisfy the fixed hybrid
// suite. Successful return implies SOPS MAC and schema verification.
func (e Engine) DecryptWithIdentities(encrypted []byte, proclamationRecipient string, identities []*age.HybridIdentity, definition schema.Definition) (*Document, string, error) {
	_, tree, recipients, err := parseEncrypted(encrypted, proclamationRecipient)
	if err != nil {
		return nil, "", err
	}
	if len(identities) == 0 {
		return nil, "", fmt.Errorf("no hybrid identity was supplied")
	}
	var dataKey []byte
	used := ""
	for _, identity := range identities {
		if identity == nil {
			continue
		}
		parsedIdentity, err := hybridage.ParseIdentity(identity.String())
		if err != nil {
			return nil, "", err
		}
		recipient := hybridage.Recipient(parsedIdentity)
		if !contains(recipients, recipient) {
			continue
		}
		for _, key := range tree.Metadata.KeyGroups[0] {
			masterKey := key.(*sopsage.MasterKey)
			if masterKey.Recipient != recipient {
				continue
			}
			if err := hybridage.ApplyIdentity(masterKey, parsedIdentity); err != nil {
				return nil, "", err
			}
			candidate, err := masterKey.Decrypt()
			if err == nil && len(candidate) == 32 {
				dataKey, used = candidate, recipient
				break
			}
			clear(candidate)
		}
		if dataKey != nil {
			break
		}
	}
	if dataKey == nil {
		return nil, "", fmt.Errorf("none of the supplied hybrid identities can unwrap the artifact data key")
	}
	defer clear(dataKey)
	document, err := decryptTree(tree, dataKey, definition)
	if err != nil {
		return nil, "", err
	}
	return document, used, nil
}

// ReplaceProclamation administratively decrypts through the current
// proclamation, preserves every guardian, installs exactly one replacement
// proclamation recipient, and fully re-encrypts under a fresh data key.
func (e Engine) ReplaceProclamation(encrypted []byte, current *age.HybridIdentity, definition schema.Definition, replacementRecipient string) ([]byte, error) {
	if _, err := hybridage.ParseRecipient(replacementRecipient); err != nil {
		return nil, err
	}
	return e.mutate(encrypted, current, definition, replacementRecipient, func(_ *Document, recipients []string) ([]string, error) {
		if len(recipients) == 0 {
			return nil, fmt.Errorf("artifact has no proclamation recipient")
		}
		if contains(recipients, replacementRecipient) {
			return nil, fmt.Errorf("replacement proclamation recipient duplicates an existing recipient")
		}
		result := append([]string{replacementRecipient}, recipients[1:]...)
		return result, nil
	})
}

// SetInscription administratively decrypts with the proclamation identity,
// changes one declared inscription, and fully re-encrypts with a fresh data key.
func (e Engine) SetInscription(encrypted []byte, proclamation *age.HybridIdentity, definition schema.Definition, name string, value any) ([]byte, error) {
	return e.mutate(encrypted, proclamation, definition, "", func(document *Document, recipients []string) ([]string, error) {
		if !declared(definition.Inscriptions, name) {
			return nil, fmt.Errorf("inscription %q is not declared by schema %q", name, definition.Reference())
		}
		document.Inscriptions[name] = value
		return recipients, nil
	})
}

// Reseal replaces every secret when selected is empty, or exactly the named
// secret otherwise. Every successful call fully re-encrypts with a fresh key.
func (e Engine) Reseal(encrypted []byte, proclamation *age.HybridIdentity, definition schema.Definition, selected string, replacements map[string]any) ([]byte, error) {
	return e.mutate(encrypted, proclamation, definition, "", func(document *Document, recipients []string) ([]string, error) {
		if selected == "" {
			document.Secrets = cloneValues(replacements)
			return recipients, nil
		}
		if !declared(definition.Secrets, selected) {
			return nil, fmt.Errorf("secret %q is not declared by schema %q", selected, definition.Reference())
		}
		if len(replacements) != 1 {
			return nil, fmt.Errorf("selected-secret reseal requires exactly one replacement")
		}
		value, exists := replacements[selected]
		if !exists {
			return nil, fmt.Errorf("selected-secret reseal has no replacement for %q", selected)
		}
		document.Secrets[selected] = value
		return recipients, nil
	})
}

func (e Engine) AddRecipient(encrypted []byte, proclamation *age.HybridIdentity, definition schema.Definition, recipient string) ([]byte, error) {
	if _, err := hybridage.ParseRecipient(recipient); err != nil {
		return nil, err
	}
	return e.mutate(encrypted, proclamation, definition, "", func(_ *Document, recipients []string) ([]string, error) {
		if contains(recipients, recipient) {
			return nil, fmt.Errorf("artifact already contains guardian recipient")
		}
		return append(recipients, recipient), nil
	})
}

func (e Engine) RemoveRecipient(encrypted []byte, proclamation *age.HybridIdentity, definition schema.Definition, recipient string) ([]byte, error) {
	if _, err := hybridage.ParseRecipient(recipient); err != nil {
		return nil, err
	}
	return e.mutate(encrypted, proclamation, definition, "", func(_ *Document, recipients []string) ([]string, error) {
		if len(recipients) == 0 || recipients[0] == recipient {
			return nil, fmt.Errorf("the proclamation recipient cannot be removed")
		}
		if !contains(recipients[1:], recipient) {
			return nil, fmt.Errorf("artifact does not contain guardian recipient")
		}
		updated := make([]string, 0, len(recipients)-1)
		for _, candidate := range recipients {
			if candidate != recipient {
				updated = append(updated, candidate)
			}
		}
		return updated, nil
	})
}

func (e Engine) mutate(encrypted []byte, proclamation *age.HybridIdentity, definition schema.Definition, resultingProclamation string, change func(*Document, []string) ([]string, error)) ([]byte, error) {
	if proclamation == nil {
		return nil, fmt.Errorf("proclamation identity is required for artifact mutation")
	}
	expected := hybridage.Recipient(proclamation)
	_, _, recipients, err := parseEncrypted(encrypted, expected)
	if err != nil {
		return nil, err
	}
	document, used, err := e.DecryptWithIdentities(encrypted, expected, []*age.HybridIdentity{proclamation}, definition)
	if err != nil {
		return nil, fmt.Errorf("proclamation authorization failed: %w", err)
	}
	defer document.Destroy()
	if used != expected {
		return nil, fmt.Errorf("artifact mutation did not use the proclamation recipient")
	}
	originalSchema := document.Schema
	recipients, err = change(document, append([]string(nil), recipients...))
	if err != nil {
		return nil, err
	}
	if document.Schema != originalSchema {
		return nil, fmt.Errorf("artifact schema reference is immutable")
	}
	if resultingProclamation == "" {
		resultingProclamation = expected
	}
	if len(recipients) == 0 || recipients[0] != resultingProclamation {
		return nil, fmt.Errorf("artifact mutation must preserve or explicitly replace exactly one leading proclamation recipient")
	}
	return e.encrypt(*document, definition, recipients[0], recipients[1:])
}

func (e Engine) encrypt(document Document, definition schema.Definition, proclamationRecipient string, guardianRecipients []string) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	if document.Schema != definition.Reference() {
		return nil, fmt.Errorf("artifact schema %q does not match resolved schema %q", document.Schema, definition.Reference())
	}
	if err := definition.ValidateArtifact(document.Secrets, document.Inscriptions); err != nil {
		return nil, err
	}
	if _, err := hybridage.ParseRecipient(proclamationRecipient); err != nil {
		return nil, fmt.Errorf("proclamation recipient: %w", err)
	}
	recipients := append([]string{proclamationRecipient}, guardianRecipients...)
	seen := make(map[string]bool, len(recipients))
	group := make(sops.KeyGroup, 0, len(recipients))
	for _, recipient := range recipients {
		if _, err := hybridage.ParseRecipient(recipient); err != nil {
			return nil, err
		}
		if seen[recipient] {
			return nil, fmt.Errorf("duplicate artifact recipient")
		}
		seen[recipient] = true
		key, err := hybridage.MasterKey(recipient)
		if err != nil {
			return nil, err
		}
		group = append(group, key)
	}
	plaintext, err := Encode(document)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return nil, fmt.Errorf("load artifact plaintext into SOPS: %w", err)
	}
	dataKey := make([]byte, 32)
	source := e.Random
	if source == nil {
		source = rand.Reader
	}
	if _, err := io.ReadFull(source, dataKey); err != nil {
		return nil, fmt.Errorf("generate SOPS data key: %w", err)
	}
	defer clear(dataKey)
	for _, key := range group {
		if err := key.Encrypt(dataKey); err != nil {
			return nil, fmt.Errorf("wrap SOPS data key: %w", err)
		}
	}
	tree := sops.Tree{Branches: branches, Metadata: sops.Metadata{EncryptedRegex: EncryptedRegex, Version: SOPSVersion, KeyGroups: []sops.KeyGroup{group}}}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypt artifact secrets: %w", err)
	}
	now := e.Now
	if now == nil {
		now = time.Now
	}
	tree.Metadata.LastModified = now().UTC().Truncate(time.Second)
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypt artifact MAC: %w", err)
	}
	output, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("emit encrypted artifact: %w", err)
	}
	if err := yamlstrict.ValidateSyntax(output); err != nil {
		return nil, fmt.Errorf("SOPS emitted invalid artifact YAML: %w", err)
	}
	if _, _, _, err := parseEncrypted(output, proclamationRecipient); err != nil {
		return nil, fmt.Errorf("validate emitted artifact: %w", err)
	}
	return output, nil
}

func parseEncrypted(encrypted []byte, proclamationRecipient string) (*encryptedWire, sops.Tree, []string, error) {
	var wire encryptedWire
	if err := yamlstrict.Unmarshal(encrypted, &wire); err != nil {
		return nil, sops.Tree{}, nil, fmt.Errorf("parse encrypted artifact: %w", err)
	}
	if wire.Format != FormatVersion {
		return nil, sops.Tree{}, nil, fmt.Errorf("unsupported artifact format %d", wire.Format)
	}
	if !schemaReferencePattern.MatchString(wire.Schema) {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact schema reference %q is invalid", wire.Schema)
	}
	if wire.Inscriptions == nil || len(wire.Secrets) == 0 {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact requires inscriptions and non-empty secrets mappings")
	}
	if err := validateValues("inscription", wire.Inscriptions); err != nil {
		return nil, sops.Tree{}, nil, err
	}
	for name, value := range wire.Inscriptions {
		if text, ok := value.(string); ok && strings.HasPrefix(text, "ENC[") {
			return nil, sops.Tree{}, nil, fmt.Errorf("encrypted value outside secrets at inscription %q", name)
		}
	}
	for name, value := range wire.Secrets {
		text, ok := value.(string)
		if !ok || !encryptedValuePattern.MatchString(text) {
			return nil, sops.Tree{}, nil, fmt.Errorf("secret %q is not an AES-256-GCM encrypted SOPS value", name)
		}
	}
	if wire.SOPS.EncryptedRegex != EncryptedRegex || wire.SOPS.Version != SOPSVersion {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact has unsupported SOPS selector or version")
	}
	if wire.SOPS.LastModified == "" || wire.SOPS.MAC == "" || !encryptedValuePattern.MatchString(wire.SOPS.MAC) {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact has invalid SOPS MAC metadata")
	}
	parsedTime, err := time.Parse(time.RFC3339, wire.SOPS.LastModified)
	if err != nil || parsedTime.UTC().Format(time.RFC3339) != wire.SOPS.LastModified {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact SOPS lastmodified must be canonical UTC RFC3339")
	}
	if len(wire.SOPS.Age) == 0 {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact has no age recipients")
	}
	rawRecipients := make([]string, len(wire.SOPS.Age))
	seen := make(map[string]bool, len(rawRecipients))
	proclamations := 0
	for index, entry := range wire.SOPS.Age {
		if err := validateAgeEnvelope(entry.Enc); err != nil {
			return nil, sops.Tree{}, nil, fmt.Errorf("artifact age recipient %d encrypted data key: %w", index, err)
		}
		if _, err := hybridage.ParseRecipient(entry.Recipient); err != nil {
			return nil, sops.Tree{}, nil, fmt.Errorf("artifact age recipient %d: %w", index, err)
		}
		if seen[entry.Recipient] {
			return nil, sops.Tree{}, nil, fmt.Errorf("artifact contains duplicate recipients")
		}
		seen[entry.Recipient] = true
		rawRecipients[index] = entry.Recipient
		if entry.Recipient == proclamationRecipient {
			proclamations++
		}
	}
	if proclamationRecipient == "" || proclamations != 1 {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact must contain exactly one tomb proclamation recipient")
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, sops.Tree{}, nil, fmt.Errorf("load encrypted artifact through SOPS: %w", err)
	}
	if tree.Metadata.EncryptedRegex != EncryptedRegex || tree.Metadata.Version != SOPSVersion || len(tree.Metadata.KeyGroups) != 1 || tree.Metadata.ShamirThreshold != 0 {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact contains unsupported SOPS metadata")
	}
	if len(tree.Metadata.KeyGroups[0]) != len(rawRecipients) {
		return nil, sops.Tree{}, nil, fmt.Errorf("artifact recipient metadata is inconsistent")
	}
	for index, key := range tree.Metadata.KeyGroups[0] {
		ageKey, ok := key.(*sopsage.MasterKey)
		if !ok || ageKey.Recipient != rawRecipients[index] {
			return nil, sops.Tree{}, nil, fmt.Errorf("artifact contains unsupported or inconsistent SOPS recipient metadata")
		}
	}
	recipients := make([]string, 1, len(rawRecipients))
	recipients[0] = proclamationRecipient
	for _, recipient := range rawRecipients {
		if recipient != proclamationRecipient {
			recipients = append(recipients, recipient)
		}
	}
	return &wire, tree, recipients, nil
}

func decryptTree(tree sops.Tree, dataKey []byte, definition schema.Definition) (*Document, error) {
	cipher := aes.NewCipher()
	computedMAC, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt artifact: %w", err)
	}
	storedMAC, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("decrypt artifact MAC: %w", err)
	}
	stored, ok := storedMAC.(string)
	if !ok || subtle.ConstantTimeCompare([]byte(stored), []byte(computedMAC)) != 1 {
		return nil, fmt.Errorf("verify artifact SOPS MAC: mismatch")
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("emit decrypted artifact: %w", err)
	}
	defer clear(plaintext)
	document, err := Decode(plaintext)
	if err != nil {
		return nil, err
	}
	if document.Schema != definition.Reference() {
		return nil, fmt.Errorf("artifact schema %q does not match resolved schema %q", document.Schema, definition.Reference())
	}
	if err := definition.ValidateArtifact(document.Secrets, document.Inscriptions); err != nil {
		return nil, err
	}
	return document, nil
}

func validateAgeEnvelope(value string) error {
	if !strings.HasPrefix(value, "-----BEGIN AGE ENCRYPTED FILE-----\n") || !strings.HasSuffix(value, "-----END AGE ENCRYPTED FILE-----\n") {
		return fmt.Errorf("must use canonical ASCII armor framing")
	}
	decoded, err := io.ReadAll(armor.NewReader(strings.NewReader(value)))
	if err != nil {
		return fmt.Errorf("invalid ASCII armor: %w", err)
	}
	defer clear(decoded)
	lines := bytes.Split(decoded, []byte{'\n'})
	if len(lines) < 5 || string(lines[0]) != "age-encryption.org/v1" {
		return fmt.Errorf("invalid age file header")
	}
	stanzas := 0
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("-> ")) {
			stanzas++
			parts := bytes.Fields(line)
			if len(parts) != 3 || string(parts[1]) != "mlkem768x25519" {
				return fmt.Errorf("age data-key envelope must contain only one native hybrid stanza")
			}
		}
	}
	if stanzas != 1 {
		return fmt.Errorf("age data-key envelope must contain exactly one native hybrid stanza")
	}
	return nil
}

func declared(fields []schema.Field, name string) bool {
	for _, field := range fields {
		if field.Name == name {
			return true
		}
	}
	return false
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func cloneValues(values map[string]any) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
