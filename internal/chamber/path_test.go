package chamber

import "testing"

func TestParseAndArtifactPath(t *testing.T) {
	path, err := Parse("Production/anthropic.v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := path.String(); got != "Production/anthropic.v1" {
		t.Fatalf("String() = %q", got)
	}
	if got := path.ArtifactPath(); got != "Production/anthropic.v1/artifact.yaml" {
		t.Fatalf("ArtifactPath() = %q", got)
	}
}

func TestParseRejectsInvalidPaths(t *testing.T) {
	for _, value := range []string{"", "/absolute", "trailing/", "double//segment", ".", "..", "a/../b", "a\\b", ".tomb", ".tomb/schemas", "a/.git/b", "a/%2f/b", "é"} {
		t.Run(value, func(t *testing.T) {
			if _, err := Parse(value); err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", value)
			}
		})
	}
}

func TestParsePreservesCaseAndAllowsCaseCollisions(t *testing.T) {
	upper, err := Parse("Production/API")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := Parse("production/api")
	if err != nil {
		t.Fatal(err)
	}
	if upper.String() == lower.String() {
		t.Fatal("chamber paths were case-folded")
	}
}
