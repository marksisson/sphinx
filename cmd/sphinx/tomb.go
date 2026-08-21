package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marksisson/sphinx/internal/relic"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/secret"
	tombpkg "github.com/marksisson/sphinx/internal/tomb"
	"github.com/spf13/cobra"
)

func newTombCommand(configFile *string) *cobra.Command {
	command := &cobra.Command{
		Use:   "tomb",
		Short: "Update, inspect, and protect tombs (git repositories)",
		Long: `Manage configured tombs and their immutable runtime revisions.

"tomb update" is the only command that advances a remote tomb lock. "tomb
protect" serves exactly the approved revision recorded in that lock.`,
	}
	command.AddCommand(
		newTombProtectCommand(configFile),
		newTombUpdateCommand(configFile),
		newTombStatusCommand(configFile),
	)
	return command
}

func newTombProtectCommand(configFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "protect [NAME]",
		Short: "protect the locked revision of a configured tomb",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			settings, err := loadTombSettings(*configFile, args)
			if err != nil {
				return err
			}
			return protectConfiguredTomb(settings)
		},
	}
}

func protectConfiguredTomb(settings *tombpkg.RuntimeSettings) error {
	options := protectOptions{
		listen: settings.Listen, tomb: settings.Locator.Base(), tombPath: settings.Path,
		tombCache: settings.Cache, decree: settings.Decree, chronicle: settings.Chronicle,
		guardian: guardianOptions{service: settings.Guardian.KeychainService, account: settings.Guardian.KeychainAccount},
	}
	if options.guardian.service == "" {
		options.guardian.service = defaultKeychainService
	}
	if options.guardian.account == "" {
		options.guardian.account = defaultKeychainAccount
	}
	if settings.Locator.Remote() {
		lock, err := tombpkg.LoadLock(settings.Lock)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("tomb %q is not locked; run sphinx tomb update %s", settings.Name, settings.Name)
			}
			return err
		}
		if err := lock.Matches(settings); err != nil {
			return err
		}
		options.tombRef = lock.Revision
		options.expectedRevision = lock.Revision
	}
	return runProtect(options)
}

func newTombUpdateCommand(configFile *string) *cobra.Command {
	var check, accept bool
	command := &cobra.Command{
		Use:   "update [NAME]",
		Short: "Validate and lock a configured tomb's current revision",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			settings, err := loadTombSettings(*configFile, args)
			if err != nil {
				return err
			}
			return updateConfiguredTomb(command.Context(), settings, check, accept)
		},
	}
	command.Flags().BoolVar(&check, "check", false, "check and validate the proposed revision without changing the lock")
	command.Flags().BoolVar(&accept, "accept", false, "write the validated lock without prompting")
	command.MarkFlagsMutuallyExclusive("check", "accept")
	return command
}

func updateConfiguredTomb(ctx context.Context, settings *tombpkg.RuntimeSettings, check, accept bool) error {
	if !settings.Locator.Remote() {
		return fmt.Errorf("local tomb %q does not need a revision lock", settings.Name)
	}
	materialized, err := settings.Locator.Materialize(ctx, settings.Cache, settings.Ref, settings.Path)
	if err != nil {
		return err
	}
	relicCount, schemaCount, err := validateTombCandidate(materialized.Root)
	if err != nil {
		return fmt.Errorf("validate proposed tomb revision %s: %w", materialized.Revision, err)
	}
	candidate := tombpkg.Lock{
		Version: 1, Tomb: settings.Name, Locator: settings.Locator.String(),
		Revision: materialized.Revision, UpdatedAt: time.Now().UTC(),
	}

	current := "unlocked"
	if lock, err := tombpkg.LoadLock(settings.Lock); err == nil {
		if err := lock.Matches(settings); err != nil {
			return err
		}
		current = lock.Revision
		if lock.Revision == candidate.Revision {
			fmt.Printf("tomb %s is already locked to %s (%d schemas, %d relics validated)\n", settings.Name, shortRevision(candidate.Revision), schemaCount, relicCount)
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	fmt.Printf("tomb:      %s\n", settings.Name)
	fmt.Printf("Locator:   %s\n", settings.Locator.String())
	if settings.Ref != "" {
		fmt.Printf("Tracking:  %s\n", settings.Ref)
	}
	fmt.Printf("Current:   %s\n", displayRevision(current))
	fmt.Printf("Proposed:  %s\n", shortRevision(candidate.Revision))
	fmt.Printf("Validated: %d schemas, %d relics\n", schemaCount, relicCount)
	if check {
		return nil
	}
	if !accept {
		answer, err := readLine("Update tomb lock? [y/N]: ")
		if err != nil {
			return err
		}
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return fmt.Errorf("tomb update declined")
		}
	}
	if err := tombpkg.WriteLock(settings.Lock, candidate); err != nil {
		return err
	}
	fmt.Printf("Locked %s to %s in %s\n", settings.Name, shortRevision(candidate.Revision), settings.Lock)
	return nil
}

func newTombStatusCommand(configFile *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status [NAME]",
		Short: "Show a configured tomb and its locked revision",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			settings, err := loadTombSettings(*configFile, args)
			if err != nil {
				return err
			}
			fmt.Printf("tomb:       %s\n", settings.Name)
			fmt.Printf("Locator:    %s\n", settings.Locator.String())
			if settings.Ref != "" {
				fmt.Printf("Tracking:   %s\n", settings.Ref)
			}
			fmt.Printf("Path:       %s\n", settings.Path)
			if !settings.Locator.Remote() {
				fmt.Println("Status:     local tomb (no lock required)")
				return nil
			}
			lock, err := tombpkg.LoadLock(settings.Lock)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					fmt.Println("Status:     unlocked")
					fmt.Printf("Next step:  sphinx tomb update %s\n", settings.Name)
					return nil
				}
				return err
			}
			if err := lock.Matches(settings); err != nil {
				return err
			}
			fmt.Printf("Revision:   %s\n", lock.Revision)
			fmt.Printf("Updated:    %s\n", lock.UpdatedAt.Format(time.RFC3339))
			fmt.Printf("Lock:       %s\n", settings.Lock)
			return nil
		},
	}
}

func loadTombSettings(configFile string, args []string) (*tombpkg.RuntimeSettings, error) {
	name := ""
	if len(args) != 0 {
		name = args[0]
	}
	return tombpkg.LoadSettings(configFile, name)
}

func validateTombCandidate(root string) (relicCount, schemaCount int, err error) {
	configuration, err := tombpkg.LoadConfiguration(root)
	if err != nil {
		return 0, 0, fmt.Errorf("load tomb configuration: %w", err)
	}
	if configuration.Recovery.Type != secret.RecoveryType {
		return 0, 0, fmt.Errorf("unsupported tomb recovery type %q", configuration.Recovery.Type)
	}
	definitions, err := schema.LoadAll(root)
	if err != nil {
		return 0, 0, err
	}
	paths, err := relic.Paths(root)
	if err != nil {
		return 0, 0, err
	}
	for _, relicPath := range paths {
		filename, err := relic.Filename(root, relicPath)
		if err != nil {
			return 0, 0, err
		}
		info, err := os.Stat(filename)
		if err != nil {
			return 0, 0, err
		}
		if info.Size() > 1<<20 {
			return 0, 0, fmt.Errorf("relic %q exceeds 1 MiB", relicPath)
		}
		encrypted, err := relic.Read(root, relicPath)
		if err != nil {
			return 0, 0, err
		}
		header, err := relic.ParseHeader(encrypted)
		if err != nil {
			return 0, 0, fmt.Errorf("validate relic %q: %w", relicPath, err)
		}
		if _, err := schema.Load(root, header.Schema); err != nil {
			return 0, 0, fmt.Errorf("validate relic %q: %w", relicPath, err)
		}
		if err := secret.ValidatePublicKey(encrypted, configuration.PublicKey); err != nil {
			return 0, 0, fmt.Errorf("validate relic %q: %w", relicPath, err)
		}
	}
	return len(paths), len(definitions), nil
}

func shortRevision(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func displayRevision(value string) string {
	if value == "unlocked" {
		return value
	}
	return shortRevision(value)
}
