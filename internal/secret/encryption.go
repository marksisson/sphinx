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
	RecoveryType    = "passphrase-v1"
	metadataVersion = "3.12.1"
)

type Decrypter struct {
	privateKeys []age.Identity
	publicKey   string
}

func GenerateKeyPair() (privateKey, publicKey string, err error) {
	generated, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	return generated.String(), generated.Recipient().String(), nil
}

func DerivePublicKey(privateKey string) (string, error) {
	parsed, err := age.ParseX25519Identity(strings.TrimSpace(privateKey))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return parsed.Recipient().String(), nil
}

func NewDecrypter(privateKey string) (*Decrypter, error) {
	parsed, err := age.ParseIdentities(strings.NewReader(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if len(parsed) != 1 {
		return nil, fmt.Errorf("exactly one guardian private key is required")
	}
	x25519, ok := parsed[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("guardian private key must be X25519")
	}
	return &Decrypter{privateKeys: parsed, publicKey: x25519.Recipient().String()}, nil
}

// Plain decrypts an encrypted YAML document and verifies its MAC.
func (d *Decrypter) Plain(_ context.Context, encrypted []byte) ([]byte, error) {
	if err := ValidatePublicKey(encrypted, d.publicKey); err != nil {
		return nil, err
	}
	return decryptWithPrivateKeys(encrypted, d.privateKeys...)
}

// Value decrypts a encrypted YAML document and returns its essence. Legacy files
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
	return nil, fmt.Errorf("decrypted document has no top-level essence field")
}

// Encrypt creates an encrypted document with one guardian public-key wrapping and one
// passphrase-based recovery wrapping.
func Encrypt(plaintext []byte, encodedPublicKey, recoveryPassphrase string) ([]byte, error) {
	if recoveryPassphrase == "" {
		return nil, fmt.Errorf("recovery passphrase cannot be empty")
	}
	publicKey, err := age.ParseX25519Recipient(strings.TrimSpace(encodedPublicKey))
	if err != nil {
		return nil, fmt.Errorf("parse guardian public key: %w", err)
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("generate relic data key: %w", err)
	}
	defer clear(dataKey)

	guardianEnvelope, err := encryptDataKey(dataKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("wrap data key with guardian public key: %w", err)
	}
	recoveryKey, err := age.NewScryptRecipient(recoveryPassphrase)
	if err != nil {
		return nil, fmt.Errorf("derive recovery key: %w", err)
	}
	recoveryEnvelope, err := encryptDataKey(dataKey, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("wrap data key for recovery: %w", err)
	}

	var document map[string]any
	if err := yaml.Unmarshal(plaintext, &document); err != nil {
		return nil, fmt.Errorf("parse plaintext relic: %w", err)
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
		return nil, fmt.Errorf("load plaintext relic: %w", err)
	}
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			EncryptedRegex: "^essence$",
			Version:        metadataVersion,
			KeyGroups: []sops.KeyGroup{{&sopsage.MasterKey{
				Recipient:    publicKey.String(),
				EncryptedKey: guardianEnvelope,
			}}},
		},
	}
	return encryptTree(store, &tree, dataKey)
}

// Update replaces plaintext in an existing document while retaining its data
// key and both key wrappings. It is used for inscription-only changes.
func Update(encrypted, plaintext []byte, privateKey string) ([]byte, error) {
	privateKeys, err := age.ParseIdentities(strings.NewReader(privateKey))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	oldTree, dataKey, err := loadAndDecrypt(store, encrypted, privateKeys...)
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
		return nil, fmt.Errorf("relic has no recovery envelope")
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

func ValidatePublicKey(encrypted []byte, expectedPublicKey string) error {
	var header struct {
		Format   int            `yaml:"format"`
		Recovery relic.Recovery `yaml:"recovery"`
	}
	if err := yaml.Unmarshal(encrypted, &header); err != nil {
		return fmt.Errorf("parse relic key metadata: %w", err)
	}
	// Legacy encrypted fixtures predate the relic schema and recovery format.
	if header.Format == 0 {
		return nil
	}
	if header.Format != relic.FormatVersion {
		return fmt.Errorf("unsupported relic format %d", header.Format)
	}
	if header.Recovery.Type != RecoveryType || header.Recovery.EncryptedDataKey == "" {
		return fmt.Errorf("relic must contain exactly one supported recovery envelope")
	}
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return fmt.Errorf("load encrypted YAML: %w", err)
	}
	if len(tree.Metadata.KeyGroups) != 1 || len(tree.Metadata.KeyGroups[0]) != 1 {
		return fmt.Errorf("relic must contain exactly one guardian public key")
	}
	masterKey, ok := tree.Metadata.KeyGroups[0][0].(*sopsage.MasterKey)
	if !ok {
		return fmt.Errorf("relic contains unsupported public-key metadata")
	}
	if expectedPublicKey != "" && masterKey.Recipient != expectedPublicKey {
		return fmt.Errorf("relic guardian public key does not match the tomb")
	}
	return nil
}

func NewRecoveryCheck(passphrase string) (string, error) {
	if passphrase == "" {
		return "", fmt.Errorf("recovery passphrase cannot be empty")
	}
	recoveryKey, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", err
	}
	check := sha256.Sum256([]byte("sphinx tomb recovery passphrase check v1"))
	return encryptDataKey(check[:], recoveryKey)
}

func VerifyRecoveryCheck(envelope, passphrase string) error {
	recoveryKey, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return err
	}
	actual, err := decryptDataKey(envelope, recoveryKey)
	if err != nil {
		return err
	}
	defer clear(actual)
	expected := sha256.Sum256([]byte("sphinx tomb recovery passphrase check v1"))
	if subtle.ConstantTimeCompare(actual, expected[:]) != 1 {
		return fmt.Errorf("recovery passphrase check failed")
	}
	return nil
}

func DecryptRecovery(encrypted []byte, passphrase string) ([]byte, error) {
	if err := ValidatePublicKey(encrypted, ""); err != nil {
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
		return nil, fmt.Errorf("relic has no supported recovery envelope")
	}
	recoveryKey, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	dataKey, err := decryptDataKey(header.Recovery.EncryptedDataKey, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt recovery data key: %w", err)
	}
	defer clear(dataKey)
	return decryptWithDataKey(encrypted, dataKey)
}

func decryptWithPrivateKeys(encrypted []byte, privateKeys ...age.Identity) ([]byte, error) {
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	_, dataKey, err := loadAndDecrypt(store, encrypted, privateKeys...)
	if err != nil {
		return nil, err
	}
	defer clear(dataKey)
	return decryptWithDataKey(encrypted, dataKey)
}

func loadAndDecrypt(store *yamlstore.Store, encrypted []byte, privateKeys ...age.Identity) (sops.Tree, []byte, error) {
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return sops.Tree{}, nil, fmt.Errorf("load encrypted YAML: %w", err)
	}
	var failures []string
	for _, group := range tree.Metadata.KeyGroups {
		for _, key := range group {
			masterKey, ok := key.(*sopsage.MasterKey)
			if !ok {
				continue
			}
			dataKey, err := decryptDataKey(masterKey.EncryptedKey, privateKeys...)
			if err == nil {
				return tree, dataKey, nil
			}
			failures = append(failures, err.Error())
		}
	}
	if len(failures) == 0 {
		return sops.Tree{}, nil, fmt.Errorf("encrypted document has no guardian public key")
	}
	return sops.Tree{}, nil, fmt.Errorf("decrypt relic data key with guardian private key: %s", strings.Join(failures, "; "))
}

func decryptWithDataKey(encrypted, dataKey []byte) ([]byte, error) {
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("load encrypted YAML: %w", err)
	}
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt encrypted document: %w", err)
	}
	originalMAC, err := cipher.Decrypt(tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("decrypt MAC: %w", err)
	}
	originalMACString, ok := originalMAC.(string)
	if !ok || subtle.ConstantTimeCompare([]byte(originalMACString), []byte(mac)) != 1 {
		return nil, fmt.Errorf("verify MAC: mismatch")
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
		return nil, fmt.Errorf("encrypt relic: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypt MAC: %w", err)
	}
	output, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf("emit encrypted relic: %w", err)
	}
	return output, nil
}

func encryptDataKey(dataKey []byte, publicKey age.Recipient) (string, error) {
	var buffer bytes.Buffer
	armored := armor.NewWriter(&buffer)
	writer, err := age.Encrypt(armored, publicKey)
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

func decryptDataKey(envelope string, privateKeys ...age.Identity) ([]byte, error) {
	reader, err := age.Decrypt(armor.NewReader(strings.NewReader(envelope)), privateKeys...)
	if err != nil {
		return nil, err
	}
	dataKey, err := io.ReadAll(io.LimitReader(reader, 33))
	if err != nil {
		return nil, err
	}
	if len(dataKey) != 32 {
		clear(dataKey)
		return nil, fmt.Errorf("invalid relic data key length %d", len(dataKey))
	}
	return dataKey, nil
}
