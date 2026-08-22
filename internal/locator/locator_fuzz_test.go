package locator

import (
	"context"
	"strings"
	"testing"
)

func FuzzParseRemote(f *testing.F) {
	for _, seed := range []string{"github:acme/secrets?ref=main", "github:acme/secrets?dir=x", "git+https://git.example.com/acme/tomb.git?rev=a3a3dda3bacf61e8a39258a0ed9c924eeca8e293", "https://example.com/archive"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if strings.HasPrefix(input, "path:") {
			return // path parsing intentionally consults Git and is covered separately
		}
		parsed, err := ParseAt(context.Background(), input, t.TempDir())
		if err != nil {
			return
		}
		if parsed.Type == TypePath || parsed.String() == "" || strings.Contains(parsed.String(), "dir=") || strings.Contains(parsed.String(), "file=") {
			t.Fatalf("accepted non-canonical repository reference %q as %#v", input, parsed)
		}
		roundTrip, err := ParseAt(context.Background(), parsed.String(), t.TempDir())
		if err != nil || roundTrip != parsed {
			t.Fatalf("canonical round trip failed: %#v, %v", roundTrip, err)
		}
	})
}
