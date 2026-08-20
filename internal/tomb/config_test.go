package tomb

import "testing"

func TestConfigurationRoundTrip(t *testing.T) {
	root := t.TempDir()
	want := Configuration{
		Format:          1,
		OnlineRecipient: "age1example",
		Recovery: RecoveryConfiguration{
			Type:           "age-scrypt-v1",
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
	if got.OnlineRecipient != want.OnlineRecipient || got.Recovery.EncryptedCheck != want.Recovery.EncryptedCheck {
		t.Fatalf("configuration = %#v, want %#v", got, want)
	}
}
