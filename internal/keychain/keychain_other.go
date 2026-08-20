//go:build !darwin

package keychain

import "errors"

var ErrNotFound = errors.New("keychain item not found")

func Get(_, _ string) (string, error) {
	return "", errors.New("macOS Keychain is only available on Darwin")
}

func Set(_, _, _ string) error {
	return errors.New("macOS Keychain is only available on Darwin")
}
