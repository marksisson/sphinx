package main

import (
	"fmt"

	"github.com/marksisson/sphinx/internal/proclamation"
	tombstate "github.com/marksisson/sphinx/internal/tomb/state"
)

func (a *app) promptProclamation(manifest tombstate.Manifest) (*proclamation.Derived, error) {
	terminal, err := a.openTerminal()
	if err != nil {
		return nil, fmt.Errorf("controlling terminal is required: %w", err)
	}
	defer terminal.Close()
	salt, err := proclamation.ParseSalt(manifest.Proclamation.Salt)
	if err != nil {
		return nil, err
	}
	var accepted *proclamation.Derived
	credential, err := proclamation.PromptVerified(terminal, func(value proclamation.Credential) (bool, error) {
		derived, err := proclamation.Derive(value, salt)
		if err != nil {
			return false, nil
		}
		public := derived.Public()
		if public.Fingerprint != manifest.Proclamation.Fingerprint || public.AgeRecipient != manifest.Proclamation.AgeRecipient {
			derived.Destroy()
			return false, nil
		}
		accepted = derived
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	credential.Destroy()
	return accepted, nil
}
