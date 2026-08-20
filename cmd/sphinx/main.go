package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	defaultKeychainService = "dev.marksisson.sphinx.age"
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
	root := &cobra.Command{
		Use:           "sphinx",
		Short:         "Protect and reveal sealed Relics",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Sphinx is an identity-aware guardian for sealed Relics.

A Tomb contains Chambers, Chambers contain Relics, and each Relic contains an
encrypted Essence plus a non-secret Inscription.`,
	}
	root.AddGroup(
		&cobra.Group{ID: "sphinx", Title: "Sphinx Commands:"},
		&cobra.Group{ID: "utility", Title: "Utility Commands:"},
	)

	guardian := newGuardianCommand()
	guardian.GroupID = "sphinx"
	protect := newProtectCommand()
	protect.GroupID = "sphinx"
	relic := newRelicCommand()
	relic.GroupID = "sphinx"
	completion := newCompletionCommand(root)
	completion.GroupID = "utility"
	root.AddCommand(guardian, protect, relic, completion)

	root.InitDefaultHelpCmd()
	for _, command := range root.Commands() {
		if command.Name() == "help" {
			command.GroupID = "utility"
			break
		}
	}
	return root
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
