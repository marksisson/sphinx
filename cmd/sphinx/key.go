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

type keyOptions struct {
	service string
	account string
}

func newKeyCommand() *cobra.Command {
	command := &cobra.Command{Use: "key", Short: "Manage Sphinx's online age identity"}
	command.AddCommand(newKeyInitCommand(), newKeyRecipientCommand())
	return command
}

func addKeyFlags(command *cobra.Command, options *keyOptions) {
	command.Flags().StringVar(&options.service, "keychain-service", defaultKeychainService, "macOS Keychain service")
	command.Flags().StringVar(&options.account, "keychain-account", defaultKeychainAccount, "macOS Keychain account")
}

func newKeyInitCommand() *cobra.Command {
	var options keyOptions
	command := &cobra.Command{
		Use:   "init",
		Short: "Generate the online age identity and store it in Keychain",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := keychain.Get(options.service, options.account); err == nil {
				return fmt.Errorf("a Sphinx age identity already exists in Keychain")
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
			fmt.Fprintln(os.Stderr, "Sphinx identity stored in macOS Keychain. Choose and securely retain a recovery passphrase before entombing a Relic.")
			return nil
		},
	}
	addKeyFlags(command, &options)
	return command
}

func newKeyRecipientCommand() *cobra.Command {
	var options keyOptions
	command := &cobra.Command{
		Use:   "recipient",
		Short: "Print Sphinx's online public age recipient",
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
	addKeyFlags(command, &options)
	return command
}
