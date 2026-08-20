package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
	"github.com/marksisson/sphinx/internal/relic"
	"go.yaml.in/yaml/v3"
)

const (
	RecoveryType = "age-scrypt-v1"
	sopsVersion  = "3.12.1"
)

type Decrypter struct {
	identities []age.Identity
	recipient  string
}

func NewDecrypter(identity string) (*Decrypter, error) {
	parsed, err := age.ParseIdentities(strings.NewReader(identity))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	if len(parsed) != 1 {
		return nil, fmt.Errorf("exactly one online age identity is required")
	}
	x25519, ok := parsed[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("online age identity must be X25519")
	}
	return &Decrypter{identities: parsed, recipient: x25519.Recipient().String()}, nil
}

// Plain decrypts a SOPS YAML document and verifies its MAC.
func (d *Decrypter) Plain(_ context.Context, encrypted []byte) ([]byte, error) {
	if err := ValidateRecipients(encrypted, d.recipient); err != nil {
		return nil, err
	}
	return decryptWithIdentity(encrypted, d.identities...)
}

// Value decrypts a SOPS YAML document and returns its Essence. Legacy files
// with a top-level value field remain readable.
func (d *Decrypter) Value(ctx context.Context, encrypted []byte) (any, error) {
	plaintext, err := d.Plain(ctx, encrypted)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var document map[string]any
	if err := yaml.Unmarshal(plaintext, &document); err != nil {
		return nil, fmt.Errorf("parse decrypted YAML: %w", err)
	}
	if essence, ok := document["essence"]; ok {
		return essence, nil
	}
	if value, ok := document["value"]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("decrypted document has no top-level Essence field")
}

// Encrypt creates a SOPS document with one online X25519 wrapping and one
// recovery wrapping made with age's native scrypt recipient.
func Encrypt(plaintext []byte, onlineRecipient, recoveryPassphrase string) ([]byte, error) {
	if recoveryPassphrase == "" {
		return nil, fmt.Errorf("recovery passphrase cannot be empty")
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(onlineRecipient))
	if err != nil {
		return nil, fmt.Errorf("parse online age recipient: %w", err)
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("generate SOPS data key: %w", err)
	}
	defer clear(dataKey)

	onlineEnvelope, err := encryptDataKey(dataKey, recipient)
	if err != nil {
		return nil, fmt.Errorf("wrap data key for online identity: %w", err)
	}
	recoveryRecipient, err := age.NewScryptRecipient(recoveryPassphrase)
	if err != nil {
		return nil, fmt.Errorf("create recovery recipient: %w", err)
	}
	recoveryEnvelope, err := encryptDataKey(dataKey, recoveryRecipient)
	if err != nil {
		return nil, fmt.Errorf("wrap data key for recovery: %w", err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(plaintext, &document); err != nil {
		return nil, fmt.Errorf("parse plaintext Relic: %w", err)
	}
	document["recovery"] = map[string]any{
		"type":               RecoveryType,
		"encrypted_data_key": recoveryEnvelope,
	}
	withRecovery, err := yaml.Marshal(document)
	if err != nil {
		return nil, err
	}
	defer clear(withRecovery)

	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile(withRecovery)
	if err != nil {
		return nil, fmt.Errorf("load plaintext Relic: %w", err)
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			EncryptedRegex: "^essence$",
			Version:        sopsVersion,
			KeyGroups: []sops.KeyGroup{{&sopsage.MasterKey{
				Recipient:    recipient.String(),
				EncryptedKey: onlineEnvelope,
			}}},
		},
	}
	return encryptTree(store, &tree, dataKey)
}

// Update replaces plaintext in an existing document while retaining its data
// key and both recipient envelopes. It is used for Inscription-only changes.
func Update(encrypted, plaintext []byte, onlineIdentity string) ([]byte, error) {
	identities, err := age.ParseIdentities(strings.NewReader(onlineIdentity))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	oldTree, dataKey, err := loadAndDecrypt(store, encrypted, identities...)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)

	var oldDocument, newDocument map[string]any
	oldPlain, err := store.EmitPlainFile(oldTree.Branches)
	if err != nil {
		return nil, err
	}
	defer clear(oldPlain)
	if err := yaml.Unmarshal(oldPlain, &oldDocument); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(plaintext, &newDocument); err != nil {
		return nil, err
	}
	recovery, ok := oldDocument["recovery"]
	if !ok {
		return nil, fmt.Errorf("Relic has no recovery envelope")
	}
	newDocument["recovery"] = recovery
	updatedPlain, err := yaml.Marshal(newDocument)
	if err != nil {
		return nil, err
	}
	defer clear(updatedPlain)
	branches, err := store.LoadPlainFile(updatedPlain)
	if err != nil {
		return nil, err
	}
	newTree := sops.Tree{Branches: branches, Metadata: oldTree.Metadata}
	newTree.Metadata.DataKey = nil
	return encryptTree(store, &newTree, dataKey)
}

func ValidateRecipients(encrypted []byte, expectedOnlineRecipient string) error {
	var header struct {
		Format   int            `yaml:"format"`
		Recovery relic.Recovery `yaml:"recovery"`
	}
	if err := yaml.Unmarshal(encrypted, &header); err != nil {
		return fmt.Errorf("parse Relic recipients: %w", err)
	}
	// Legacy SOPS fixtures predate the Relic schema and recovery format.
	if header.Format == 0 {
		return nil
	}
	if header.Format != relic.FormatVersion {
		return fmt.Errorf("unsupported Relic format %d", header.Format)
	}
	if header.Recovery.Type != RecoveryType || header.Recovery.EncryptedDataKey == "" {
		return fmt.Errorf("Relic must contain exactly one supported recovery envelope")
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return fmt.Errorf("load SOPS YAML: %w", err)
	}
	if len(tree.Metadata.KeyGroups) != 1 || len(tree.Metadata.KeyGroups[0]) != 1 {
		return fmt.Errorf("Relic must contain exactly one online SOPS recipient")
	}
	masterKey, ok := tree.Metadata.KeyGroups[0][0].(*sopsage.MasterKey)
	if !ok {
		return fmt.Errorf("Relic online recipient must use age")
	}
	if expectedOnlineRecipient != "" && masterKey.Recipient != expectedOnlineRecipient {
		return fmt.Errorf("Relic online recipient does not match the Tomb")
	}
	return nil
}

func NewRecoveryCheck(passphrase string) (string, error) {
	if passphrase == "" {
		return "", fmt.Errorf("recovery passphrase cannot be empty")
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", err
	}
	check := sha256.Sum256([]byte("sphinx Tomb recovery passphrase check v1"))
	return encryptDataKey(check[:], recipient)
}

func VerifyRecoveryCheck(envelope, passphrase string) error {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return err
	}
	actual, err := decryptDataKey(envelope, identity)
	if err != nil {
		return err
	}
	defer clear(actual)
	expected := sha256.Sum256([]byte("sphinx Tomb recovery passphrase check v1"))
	if subtle.ConstantTimeCompare(actual, expected[:]) != 1 {
		return fmt.Errorf("recovery passphrase check failed")
	}
	return nil
}

func DecryptRecovery(encrypted []byte, passphrase string) ([]byte, error) {
	if err := ValidateRecipients(encrypted, ""); err != nil {
		return nil, err
	}
	if passphrase == "" {
		return nil, fmt.Errorf("recovery passphrase cannot be empty")
	}
	var header struct {
		Recovery relic.Recovery `yaml:"recovery"`
	}
	if err := yaml.Unmarshal(encrypted, &header); err != nil {
		return nil, fmt.Errorf("parse recovery envelope: %w", err)
	}
	if header.Recovery.Type != RecoveryType || header.Recovery.EncryptedDataKey == "" {
		return nil, fmt.Errorf("Relic has no supported recovery envelope")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	dataKey, err := decryptDataKey(header.Recovery.EncryptedDataKey, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovery data key: %w", err)
	}
	defer clear(dataKey)
	return decryptWithDataKey(encrypted, dataKey)
}

func decryptWithIdentity(encrypted []byte, identities ...age.Identity) ([]byte, error) {
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	_, dataKey, err := loadAndDecrypt(store, encrypted, identities...)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	return decryptWithDataKey(encrypted, dataKey)
}

func loadAndDecrypt(store *yamlstore.Store, encrypted []byte, identities ...age.Identity) (sops.Tree, []byte, error) {
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return sops.Tree{}, nil, fmt.Errorf("load SOPS YAML: %w", err)
	}
	var failures []string
	for _, group := range tree.Metadata.KeyGroups {
		for _, key := range group {
			masterKey, ok := key.(*sopsage.MasterKey)
			if !ok {
				continue
			}
			dataKey, err := decryptDataKey(masterKey.EncryptedKey, identities...)
			if err == nil {
				return tree, dataKey, nil
			}
			failures = append(failures, err.Error())
		}
	}
	if len(failures) == 0 {
		return sops.Tree{}, nil, fmt.Errorf("SOPS document has no age recipient")
	}
	return sops.Tree{}, nil, fmt.Errorf("decrypt SOPS data key with age: %s", strings.Join(failures, "; "))
}

func decryptWithDataKey(encrypted, dataKey []byte) ([]byte, error) {
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("load SOPS YAML: %w", err)
	}
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt SOPS document: %w", err)
	}
	originalMAC, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("decrypt SOPS MAC: %w", err)
	}
	originalMACString, ok := originalMAC.(string)
	if !ok || subtle.ConstantTimeCompare([]byte(originalMACString), []byte(mac)) != 1 {
		return nil, fmt.Errorf("verify SOPS integrity: MAC mismatch")
	}
	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("emit decrypted YAML: %w", err)
	}
	return plaintext, nil
}

func encryptTree(store *yamlstore.Store, tree *sops.Tree, dataKey []byte) ([]byte, error) {
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("encrypt Relic: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypt SOPS MAC: %w", err)
	}
	output, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf("emit encrypted Relic: %w", err)
	}
	return output, nil
}

func encryptDataKey(dataKey []byte, recipient age.Recipient) (string, error) {
	var buffer bytes.Buffer
	armored := armor.NewWriter(&buffer)
	writer, err := age.Encrypt(armored, recipient)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(dataKey); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	if err := armored.Close(); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func decryptDataKey(envelope string, identities ...age.Identity) ([]byte, error) {
	reader, err := age.Decrypt(armor.NewReader(strings.NewReader(envelope)), identities...)
	if err != nil {
		return nil, err
	}
	dataKey, err := io.ReadAll(io.LimitReader(reader, 33))
	if err != nil {
		return nil, err
	}
	if len(dataKey) != 32 {
		clear(dataKey)
		return nil, fmt.Errorf("invalid SOPS data key length %d", len(dataKey))
	}
	return dataKey, nil
}
