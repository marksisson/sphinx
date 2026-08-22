package seeker

import "testing"

func TestIdentityAllowsLoginOrTagsIndependently(t *testing.T) {
	if _, err := New("user@example.com", nil); err != nil {
		t.Fatal(err)
	}
	identity, err := New("", []string{"tag:ci", "tag:release"})
	if err != nil {
		t.Fatal(err)
	}
	identity.Tags[0] = "changed"
	if _, err := New("", nil); err == nil {
		t.Fatal("New unexpectedly accepted an empty seeker")
	}
	if _, err := New("user@example.com", []string{"tag:ci", "tag:ci"}); err == nil {
		t.Fatal("New unexpectedly accepted duplicate tags")
	}
}
