package secret

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
	"go.yaml.in/yaml/v3"
)

type Decrypter struct {
	identities sopsage.ParsedIdentities
}

func NewDecrypter(identity string) (*Decrypter, error) {
	var identities sopsage.ParsedIdentities
	if err := identities.Import(identity); err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	return &Decrypter{identities: identities}, nil
}

// Value decrypts a SOPS YAML document, verifies its MAC, and returns only its
// top-level value field. Identity material is injected directly into a local
// age-only SOPS key service and is never placed in an environment variable or
// temporary file.
func (d *Decrypter) Value(ctx context.Context, encrypted []byte) (any, error) {
	store := yamlstore.NewStore(&config.YAMLStoreConfig{})
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("load SOPS YAML: %w", err)
	}

	client := keyservice.NewCustomLocalClient(&ageKeyService{identities: d.identities})
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{client}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt SOPS data key with age: %w", err)
	}
	defer clear(dataKey)

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("decrypt SOPS document: %w", err)
	}
	originalMAC, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		dataKey,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt SOPS MAC: %w", err)
	}
	originalMACString, ok := originalMAC.(string)
	if !ok {
		return nil, fmt.Errorf("verify SOPS integrity: MAC is not a string")
	}
	if subtle.ConstantTimeCompare([]byte(originalMACString), []byte(mac)) != 1 {
		return nil, fmt.Errorf("verify SOPS integrity: MAC mismatch")
	}

	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("emit decrypted YAML: %w", err)
	}
	defer clear(plaintext)

	var document map[string]any
	if err := yaml.Unmarshal(plaintext, &document); err != nil {
		return nil, fmt.Errorf("parse decrypted YAML: %w", err)
	}
	value, ok := document["value"]
	if !ok {
		return nil, fmt.Errorf("decrypted document has no top-level value field")
	}
	return value, nil
}

type ageKeyService struct {
	keyservice.UnimplementedKeyServiceServer
	identities sopsage.ParsedIdentities
}

func (s *ageKeyService) Decrypt(_ context.Context, request *keyservice.DecryptRequest) (*keyservice.DecryptResponse, error) {
	if request == nil || request.Key == nil {
		return nil, fmt.Errorf("missing SOPS master key")
	}
	ageKey := request.Key.GetAgeKey()
	if ageKey == nil {
		return nil, fmt.Errorf("master key type is not age")
	}

	masterKey := &sopsage.MasterKey{
		Recipient:    ageKey.Recipient,
		EncryptedKey: string(request.Ciphertext),
	}
	s.identities.ApplyToMasterKey(masterKey)
	plaintext, err := masterKey.Decrypt()
	if err != nil {
		return nil, fmt.Errorf("decrypt age data key: %w", err)
	}
	return &keyservice.DecryptResponse{Plaintext: plaintext}, nil
}
