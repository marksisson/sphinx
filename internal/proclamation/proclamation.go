// Package proclamation implements generated administrative credentials and
// their deterministic, domain-separated hybrid key derivation.
package proclamation

// Credential holds proclamation bytes and redacts all conventional formatting.
// Callers must destroy it after derivation.
type Credential struct {
	value []byte
}

func NewCredential(value []byte) Credential {
	return Credential{value: append([]byte(nil), value...)}
}

// WithBytes lends the credential to a derivation callback without returning
// the backing slice.
func (Credential) String() string   { return "[REDACTED]" }
func (Credential) GoString() string { return "[REDACTED]" }

func (c Credential) WithBytes(use func([]byte) error) error {
	copyValue := append([]byte(nil), c.value...)
	defer clear(copyValue)
	return use(copyValue)
}

func (c *Credential) Destroy() {
	clear(c.value)
	c.value = nil
}
