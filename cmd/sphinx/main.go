package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	cliresult "github.com/marksisson/sphinx/internal/cli/result"
	"github.com/spf13/cobra"
)

func main() { os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, nil)) }

func runCLI(args []string, out, errOut io.Writer, injected *app) int {
	a := injected
	if a == nil {
		var err error
		a, err = newApp(out, errOut)
		if err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return cliresult.EXSoftware
		}
	} else {
		a.out = out
		a.errOut = errOut
	}
	if err := a.prepareCommand(); err != nil {
		jsonRequested := false
		for _, arg := range args {
			if arg == "--json" || arg == "--json=true" {
				jsonRequested = true
				break
			}
		}
		if jsonRequested {
			code, writeErr := cliresult.WriteError(errOut, err)
			if writeErr != nil {
				return cliresult.EXIOErr
			}
			return code
		}
		failure := cliresult.Classify(err)
		fmt.Fprintln(errOut, "error:", failure.Error())
		return failure.Exit
	}
	root := newRootCommand(a)
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errOut)
	err := root.Execute()
	if err == nil {
		return 0
	}
	if a.json {
		code, writeErr := cliresult.WriteError(errOut, err)
		if writeErr != nil {
			return cliresult.EXIOErr
		}
		return code
	}
	failure := cliresult.Classify(err)
	fmt.Fprintln(errOut, "error:", failure.Error())
	return failure.Exit
}

func newRootCommand(a *app) *cobra.Command {
	root := &cobra.Command{Use: "sphinx", Short: "Manage signed tombs and reveal authorized secrets", SilenceErrors: true, SilenceUsage: true, PersistentPreRunE: func(*cobra.Command, []string) error { return a.prepareCommand() }, Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		return cliresult.Usage(fmt.Errorf("a command is required; run %s --help", c.CommandPath()))
	}}
	root.PersistentFlags().StringVar(&a.globalConfig, "config", a.globalConfig, "optional global tomb-alias configuration")
	root.PersistentFlags().BoolVar(&a.json, "json", false, "emit one version-1 JSON envelope")
	root.PersistentFlags().BoolVar(&a.quiet, "quiet", false, "suppress nonessential human output")
	root.PersistentFlags().BoolVar(&a.noColor, "no-color", false, "disable color output")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return cliresult.Usage(err) })
	root.AddCommand(newTombCommand(a), newArtifactCommand(a), newGuardianCommand(a), newDecreeCommand(a), newProclamationCommand(a), newCompletionCommand(root))
	root.SetHelpCommand(newHelpCommand(root, a))
	return root
}

func commandGroup(use, short string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		return cliresult.Usage(fmt.Errorf("a subcommand is required for %s", c.CommandPath()))
	}}
}

func newHelpCommand(root *cobra.Command, a *app) *cobra.Command {
	return &cobra.Command{Use: "help [command...]", Args: cobra.ArbitraryArgs, RunE: func(_ *cobra.Command, args []string) error {
		target := root
		if len(args) > 0 {
			found, remaining, err := root.Find(args)
			if err != nil {
				return cliresult.Usage(err)
			}
			if len(remaining) != 0 {
				return cliresult.Usage(fmt.Errorf("unknown help command %q", strings.Join(remaining, " ")))
			}
			target = found
		}
		var rendered bytes.Buffer
		target.SetOut(&rendered)
		err := target.Help()
		target.SetOut(root.OutOrStdout())
		if err != nil {
			return err
		}
		text := rendered.String()
		return a.success(map[string]any{"help": text}, func(w io.Writer) error { _, err := io.WriteString(w, text); return err }, nil)
	}}
}

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Args: cobra.ExactArgs(1), ValidArgs: []string{"bash", "zsh", "fish", "powershell"}, RunE: func(_ *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(root.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(root.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(root.OutOrStdout(), true)
		case "powershell":
			return root.GenPowerShellCompletion(root.OutOrStdout())
		default:
			return cliresult.Usage(fmt.Errorf("unsupported shell %q", args[0]))
		}
	}}
}
