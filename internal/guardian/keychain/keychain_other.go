//go:build !darwin

package keychain

import "errors"

var (
	ErrNotFound      = errors.New("keychain item not found")
	ErrAlreadyExists = errors.New("keychain item already exists")
	errUnsupported   = errors.New("macOS Keychain is only available on Darwin")
)

type Item struct {
	Account        string
	Data           []byte
	Synchronizable bool
}

func Add(_, _, _ string, _ []byte, _ bool) error   { return errUnsupported }
func GetExact(_, _ string, _ bool) ([]byte, error) { return nil, errUnsupported }
func DeleteExact(_, _ string, _ bool) error        { return errUnsupported }
func List(_ string) ([]Item, error)                { return nil, errUnsupported }
