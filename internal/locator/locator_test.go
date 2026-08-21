package locator

import "testing"

func TestParse(t *testing.T) {
	const revision = "a3a3dda3bacf61e8a39258a0ed9c924eeca8e293"
	tests := []struct {
		input string
		want  Locator
	}{
		{"github:example/secrets-tomb", Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Host: "github.com"}},
		{"github:example/secrets-tomb/release-20.09", Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Ref: "release-20.09", Host: "github.com"}},
		{"github:example/secrets-tomb/pull/357207/head", Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Ref: "pull/357207/head", Host: "github.com"}},
		{"github:example/secrets-tomb/" + revision, Locator{Type: TypeGitHub, Owner: "example", Repo: "secrets-tomb", Rev: revision, Host: "github.com"}},
		{"github:example/creative-tomb?dir=blender", Locator{Type: TypeGitHub, Owner: "example", Repo: "creative-tomb", Dir: "blender", Host: "github.com"}},
		{"git+https://github.com/example/secrets-tomb", Locator{Type: TypeGit, URL: "https://github.com/example/secrets-tomb"}},
		{"git+https://github.com/example/secrets-tomb?ref=master", Locator{Type: TypeGit, URL: "https://github.com/example/secrets-tomb", Ref: "master"}},
		{"git+https://github.com/example/secrets-tomb?ref=master&rev=" + revision, Locator{Type: TypeGit, URL: "https://github.com/example/secrets-tomb", Ref: "master", Rev: revision}},
		{"git+ssh://git@github.com/example/tomb.git?ref=main&dir=secrets", Locator{Type: TypeGit, URL: "ssh://git@github.com/example/tomb.git", Ref: "main", Dir: "secrets"}},
		{"./secrets", Locator{Type: TypePath, Path: "./secrets"}},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := Parse(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("Parse() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseRejectsUnsafeAndUnsupportedLocators(t *testing.T) {
	tests := []string{
		"", "github:owner", "github:owner/repo?token=secret",
		"github:owner/repo?dir=../escape", "github:owner/repo?ref=main&ref=other",
		"git+file:///tmp/tomb", "git+https://user:secret@example.com/tomb",
		"git+ssh://root@example.com/tomb", "https://example.com/tomb.tar.gz",
	}
	for _, input := range tests {
		if _, err := Parse(input); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", input)
		}
	}
}

func TestLocatorFormatting(t *testing.T) {
	parsed, err := Parse("github:example/secrets-tomb/pull/357207/head?dir=secrets")
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Base(); got != "github:example/secrets-tomb" {
		t.Fatalf("Base() = %q", got)
	}
	if got := parsed.String(); got != "github:example/secrets-tomb/pull/357207/head?dir=secrets" {
		t.Fatalf("String() = %q", got)
	}
	if got := parsed.CloneURL(); got != "https://github.com/example/secrets-tomb.git" {
		t.Fatalf("CloneURL() = %q", got)
	}
}
