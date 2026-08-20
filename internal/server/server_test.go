package server

import "testing"

func TestValidatePath(t *testing.T) {
	valid := []string{
		"openai/api/key",
		"aws/credentials/access_key_id",
		"service.with-dots/value_1",
	}
	for _, value := range valid {
		if err := ValidatePath(value); err != nil {
			t.Errorf("ValidatePath(%q): %v", value, err)
		}
	}

	invalid := []string{
		"",
		"/absolute",
		"trailing/",
		"../escape",
		"a/../b",
		"a//b",
		"a b/c",
		"a/%2e%2e/b",
	}
	for _, value := range invalid {
		if err := ValidatePath(value); err == nil {
			t.Errorf("ValidatePath(%q) unexpectedly succeeded", value)
		}
	}
}
