package chamber

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"production/api", "../escape", ".tomb/schemas", "a//b", "Production/API", "a\\b", "é"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := Parse(input)
		if err != nil {
			return
		}
		if parsed.String() != input || parsed.ArtifactPath() != input+"/artifact.yaml" {
			t.Fatalf("accepted chamber was not preserved exactly: %q", input)
		}
		if strings.ContainsAny(input, "\\%") || strings.HasPrefix(input, ".tomb") {
			t.Fatalf("accepted unsafe chamber %q", input)
		}
	})
}
