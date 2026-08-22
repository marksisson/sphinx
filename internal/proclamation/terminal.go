package proclamation

import (
	"crypto/subtle"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const MaximumAttempts = 3

type Terminal interface {
	Write([]byte) (int, error)
	ReadPassword(prompt []byte) ([]byte, error)
}

type ControllingTerminal struct{ file *os.File }

func OpenControllingTerminal() (*ControllingTerminal, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open controlling terminal: %w", err)
	}
	if !term.IsTerminal(int(file.Fd())) {
		file.Close()
		return nil, fmt.Errorf("controlling terminal is unavailable")
	}
	return &ControllingTerminal{file: file}, nil
}

func (t *ControllingTerminal) Close() error                    { return t.file.Close() }
func (t *ControllingTerminal) Write(value []byte) (int, error) { return t.file.Write(value) }
func (t *ControllingTerminal) ReadPassword(prompt []byte) ([]byte, error) {
	if _, err := t.file.Write(prompt); err != nil {
		return nil, err
	}
	value, err := term.ReadPassword(int(t.file.Fd()))
	_, newlineErr := t.file.Write([]byte("\n"))
	if err != nil {
		return nil, err
	}
	return value, newlineErr
}

// GenerateAndConfirm writes a generated proclamation only to a controlling
// terminal and requires exact re-entry. The returned credential remains owned
// by the caller and must be destroyed.
func GenerateAndConfirm(terminal Terminal, source io.Reader) (Credential, error) {
	if terminal == nil {
		return Credential{}, fmt.Errorf("controlling terminal is required")
	}
	credential, err := Generate(source)
	if err != nil {
		return Credential{}, err
	}
	var displayed []byte
	if err := credential.WithBytes(func(value []byte) error {
		displayed = append([]byte("Generated proclamation (store it securely; it will not be shown again):\n"), value...)
		displayed = append(displayed, '\n')
		written, err := terminal.Write(displayed)
		if err == nil && written != len(displayed) {
			err = io.ErrShortWrite
		}
		return err
	}); err != nil {
		credential.Destroy()
		clear(displayed)
		return Credential{}, fmt.Errorf("display generated proclamation: %w", err)
	}
	clear(displayed)
	for attempt := 0; attempt < MaximumAttempts; attempt++ {
		confirmation, err := terminal.ReadPassword([]byte("Re-enter generated proclamation: "))
		if err != nil {
			credential.Destroy()
			return Credential{}, fmt.Errorf("read proclamation confirmation: %w", err)
		}
		matched := false
		_ = credential.WithBytes(func(value []byte) error {
			matched = len(value) == len(confirmation) && subtle.ConstantTimeCompare(value, confirmation) == 1
			return nil
		})
		clear(confirmation)
		if matched {
			return credential, nil
		}
	}
	credential.Destroy()
	return Credential{}, fmt.Errorf("proclamation confirmation failed after three attempts")
}

// PromptVerified allows at most three controlling-terminal attempts and only
// returns a credential accepted by the caller's public-bundle verifier.
func PromptVerified(terminal Terminal, verify func(Credential) (bool, error)) (Credential, error) {
	if terminal == nil || verify == nil {
		return Credential{}, fmt.Errorf("controlling terminal and proclamation verifier are required")
	}
	for attempt := 0; attempt < MaximumAttempts; attempt++ {
		value, err := terminal.ReadPassword([]byte("Proclamation: "))
		if err != nil {
			return Credential{}, fmt.Errorf("read proclamation: %w", err)
		}
		credential := NewCredential(value)
		clear(value)
		accepted, err := verify(credential)
		if err != nil {
			credential.Destroy()
			return Credential{}, err
		}
		if accepted {
			return credential, nil
		}
		credential.Destroy()
	}
	return Credential{}, fmt.Errorf("proclamation verification failed after three attempts")
}
