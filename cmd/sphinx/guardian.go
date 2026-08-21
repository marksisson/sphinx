package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/marksisson/sphinx/internal/secret"
	"github.com/spf13/cobra"
)

type guardianOptions struct {
	service string
	account string
}

func newGuardianCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "guardian",
		Short: "Manage the guardian's cryptographic keys",
		Long: `Manage the guardian's cryptographic keys.

awaken creates and safeguards the guardian's private key. behold displays the
guardian's public key, which is used to seal relics for this guardian.`,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unknown command %q for %q", args[0], command.CommandPath())
			}
			return command.Help()
		},
	}
	command.AddCommand(newGuardianAwakenCommand(), newGuardianBeholdCommand())
	return command
}

func addGuardianFlags(command *cobra.Command, options *guardianOptions) {
	command.Flags().StringVar(&options.service, "keychain-service", defaultKeychainService, "macOS keychain service")
	command.Flags().StringVar(&options.account, "keychain-account", defaultKeychainAccount, "macOS keychain account")
}

func newGuardianAwakenCommand() *cobra.Command {
	var options guardianOptions
	command := &cobra.Command{
		Use:   "awaken",
		Short: "generate and store the guardian's private key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := keychain.Get(options.service, options.account); err == nil {
				return fmt.Errorf("the guardian's private key already exists in the Keychain")
			} else if !errors.Is(err, keychain.ErrNotFound) {
				return err
			}
			privateKey, publicKey, err := secret.GenerateKeyPair()
			if err != nil {
				return err
			}
			if err := keychain.Set(options.service, options.account, privateKey); err != nil {
				return err
			}
			fmt.Println(publicKey)
			fmt.Fprintln(os.Stderr, "guardian awakened and private key stored in the macOS Keychain. Choose and securely retain a recovery passphrase before entombing a relic.")
			return nil
		},
	}
	addGuardianFlags(command, &options)
	return command
}

func newGuardianBeholdCommand() *cobra.Command {
	var options guardianOptions
	command := &cobra.Command{
		Use:   "behold",
		Short: "print the guardian's public key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			encoded, err := keychain.Get(options.service, options.account)
			if err != nil {
				return err
			}
			publicKey, err := secret.DerivePublicKey(strings.TrimSpace(encoded))
			if err != nil {
				return err
			}
			fmt.Println(publicKey)
			return nil
		},
	}
	addGuardianFlags(command, &options)
	return command
}
