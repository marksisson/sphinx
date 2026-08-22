package guardian

import "testing"

func TestGuardianDomainIdentifiers(t *testing.T) {
	name, err := ParseName("personal-guardian")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := ParseProvider("apple-icloud-keychain")
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Name: name, Provider: provider}
	if selection.Name != "personal-guardian" || selection.Provider != AppleICloudKeychain {
		t.Fatalf("unexpected selection: %#v", selection)
	}
	for _, invalid := range []string{"", "bad/name", " leading"} {
		if _, err := ParseName(invalid); err == nil {
			t.Errorf("ParseName(%q) unexpectedly succeeded", invalid)
		}
	}
	if _, err := ParseProvider("filesystem"); err == nil {
		t.Fatal("ParseProvider unexpectedly accepted filesystem")
	}
}
