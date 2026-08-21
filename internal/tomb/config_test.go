package tomb

import "testing"

func TestConfigurationRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := Configuration{
		Format:    1,
		PublicKey: "public-key-example",
		Recovery: RecoveryConfiguration{
			Type:           "passphrase-v1",
			EncryptedCheck: "encrypted-check",
		},
	}
	if err := WriteConfiguration(root, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicKey != want.PublicKey || got.Recovery.EncryptedCheck != want.Recovery.EncryptedCheck {
		t.Fatalf("configuration = %#v, want %#v", got, want)
	}
}
