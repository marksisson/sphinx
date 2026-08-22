// Package guardian defines provider-neutral guardian domain identifiers. It has
// no credential-store or network dependencies.
package guardian

import (
	"fmt"
	"regexp"
	"runtime"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type Name string

type Provider string

const (
	AppleICloudKeychain Provider = "apple-icloud-keychain"
	AppleLoginKeychain  Provider = "apple-login-keychain"
	Environment         Provider = "environment"
)

func ParseName(value string) (Name, error) {
	if !namePattern.MatchString(value) {
		return "", fmt.Errorf("guardian name %q is invalid", value)
	}
	return Name(value), nil
}

func DefaultProvider() (Provider, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("this platform has no default guardian provider")
	}
	return AppleICloudKeychain, nil
}

func ParseProvider(value string) (Provider, error) {
	provider := Provider(value)
	switch provider {
	case AppleICloudKeychain, AppleLoginKeychain, Environment:
		return provider, nil
	default:
		return "", fmt.Errorf("guardian provider %q is unsupported", value)
	}
}

// Selection identifies one provider-owned guardian without carrying private
// identity material.
type Selection struct {
	Name     Name
	Provider Provider
}
