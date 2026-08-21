package main

import (
	"fmt"
	"os"

	tombpkg "github.com/marksisson/sphinx/internal/tomb"
	"github.com/spf13/cobra"
)

const (
	defaultKeychainService = "dev.marksisson.sphinx.keys"
	defaultKeychainAccount = "sphinx-v1"
)

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	configFile := ""
	root := &cobra.Command{
		Use:           "sphinx",
		Short:         "protect and reveal relics",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Sphinx is an identity-aware guardian that controls access to relics.

A tomb contains chambers, chambers contain relics, and each relic contains an
encrypted essence plus a non-secret inscription.`,
	}
	root.AddGroup(
		&cobra.Group{ID: "sphinx", Title: "Sphinx Commands:"},
		&cobra.Group{ID: "utility", Title: "Utility Commands:"},
	)

	root.PersistentFlags().StringVar(&configFile, "config", tombDefaultSettingsPath(), "sphinx configuration file")

	guardian := newGuardianCommand()
	guardian.GroupID = "sphinx"
	tomb := newTombCommand(&configFile)
	tomb.GroupID = "sphinx"
	relic := newRelicCommand()
	relic.GroupID = "sphinx"
	completion := newCompletionCommand(root)
	completion.GroupID = "utility"
	root.AddCommand(guardian, tomb, relic, completion)

	root.InitDefaultHelpCmd()
	for _, command := range root.Commands() {
		if command.Name() == "help" {
			command.GroupID = "utility"
			break
		}
	}
	return root
}

func tombDefaultSettingsPath() string {
	return tombpkg.DefaultSettingsPath()
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	command := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion code",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletion(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
		},
	}
	return command
}
