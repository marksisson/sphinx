package yamlstrict

import "testing"

func FuzzValidateSyntax(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("version: 1\n"),
		[]byte("value: &anchor secret\ncopy: *anchor\n"),
		[]byte("value: !custom secret\n"),
		[]byte("value: first\nvalue: second\n"),
		[]byte("base: &base\n  value: x\nmerged:\n  <<: *base\n"),
		[]byte("version: 1\n---\nversion: 2\n"),
		[]byte("1: value\n"),
		[]byte{0xef, 0xbb, 0xbf, 'x', ':', ' ', 'y', '\n'},
		[]byte("x: y\r\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		err := ValidateSyntax(input)
		if err == nil {
			if byteErr := ValidateBytes(input); byteErr != nil {
				t.Fatalf("syntax accepted invalid framing: %v", byteErr)
			}
		}
	})
}
