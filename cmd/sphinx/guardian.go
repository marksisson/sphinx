package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/marksisson/sphinx/internal/keychain"
	"github.com/spf13/cobra"
)

type guardianOptions struct {
	service string
	account string
}

func newGuardianCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "guardian",
		Short: "Manage the Guardian's online age identity",
		Long: `Manage the Guardian's Keychain-backed online age identity.

Awaken creates the private identity. Cartouche prints the corresponding public
age recipient used to seal Relics for this Guardian.`,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("unknown command %q for %q", args[0], command.CommandPath())
			}
			return command.Help()
		},
	}
	command.AddCommand(newGuardianAwakenCommand(), newGuardianCartoucheCommand())
	return command
}

func addGuardianFlags(command *cobra.Command, options *guardianOptions) {
	command.Flags().StringVar(&options.service, "keychain-service", defaultKeychainService, "macOS Keychain service")
	command.Flags().StringVar(&options.account, "keychain-account", defaultKeychainAccount, "macOS Keychain account")
}

func newGuardianAwakenCommand() *cobra.Command {
	var options guardianOptions
	command := &cobra.Command{
		Use:   "awaken",
		Short: "Generate and store the Guardian's online age identity",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := keychain.Get(options.service, options.account); err == nil {
				return fmt.Errorf("a Guardian age identity already exists in Keychain")
			} else if !errors.Is(err, keychain.ErrNotFound) {
				return err
			}
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				return fmt.Errorf("generate age identity: %w", err)
			}
			if err := keychain.Set(options.service, options.account, identity.String()); err != nil {
				return err
			}
			fmt.Println(identity.Recipient().String())
			fmt.Fprintln(os.Stderr, "Guardian awakened and identity stored in macOS Keychain. Choose and securely retain a recovery passphrase before entombing a Relic.")
			return nil
		},
	}
	addGuardianFlags(command, &options)
	return command
}

func newGuardianCartoucheCommand() *cobra.Command {
	var options guardianOptions
	command := &cobra.Command{
		Use:   "cartouche",
		Short: "Print the Guardian's public age recipient",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			encoded, err := keychain.Get(options.service, options.account)
			if err != nil {
				return err
			}
			identity, err := age.ParseX25519Identity(strings.TrimSpace(encoded))
			if err != nil {
				return fmt.Errorf("parse Keychain age identity: %w", err)
			}
			fmt.Println(identity.Recipient().String())
			return nil
		},
	}
	addGuardianFlags(command, &options)
	return command
}
