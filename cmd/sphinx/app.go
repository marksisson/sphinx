package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	cliresult "github.com/marksisson/sphinx/internal/cli/result"
	"github.com/marksisson/sphinx/internal/config"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	gitruntime "github.com/marksisson/sphinx/internal/git/runtime"
	"github.com/marksisson/sphinx/internal/guardian"
	guardianstore "github.com/marksisson/sphinx/internal/guardian/store"
	"github.com/marksisson/sphinx/internal/hardening"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/reveal"
	"github.com/marksisson/sphinx/internal/seeker"
	"golang.org/x/term"
)

type app struct {
	out, errOut          io.Writer
	json, quiet, noColor bool
	globalConfig         string
	cwd                  func() (string, error)
	materializer         gitresource.Materializer
	guardians            guardianOperations
	seekers              reveal.SeekerResolver
	openTerminal         func() (commandTerminal, error)
	outputIsTerminal     func(io.Writer) bool
	renderHelpGraphic    func(io.Writer) bool
	detectHelpBackground func(io.Writer) helpBackground
	disableCoreDumps     func() error
	newGuardianStore     func() guardianOperations
	securityPrepared     bool
}

type guardianOperations interface {
	Create(guardian.Name, guardian.Provider) (*guardian.Record, error)
	Get(guardian.Name, guardian.Provider) (*guardian.Record, error)
	List(guardian.Provider) ([]*guardian.Record, error)
	Delete(guardian.Name, guardian.Provider) error
}

type commandTerminal interface {
	proclamation.Terminal
	io.Closer
}

func newApp(out, errOut io.Writer) (*app, error) {
	global, err := globalConfigPath()
	if err != nil {
		return nil, err
	}
	cache, err := gitresource.DefaultCacheRoot()
	if err != nil {
		return nil, err
	}
	return &app{out: out, errOut: errOut, globalConfig: global, cwd: os.Getwd, materializer: gitresource.Materializer{CacheRoot: cache}, seekers: seeker.NewTailscaleResolver(), openTerminal: func() (commandTerminal, error) { return proclamation.OpenControllingTerminal() }, outputIsTerminal: func(w io.Writer) bool { f, ok := w.(*os.File); return ok && term.IsTerminal(int(f.Fd())) }, renderHelpGraphic: renderKittySphinx, detectHelpBackground: detectTerminalBackground, disableCoreDumps: hardening.DisableCoreDumps, newGuardianStore: func() guardianOperations { store := guardianstore.New(); return store }}, nil
}
func globalConfigPath() (string, error) { return config.GlobalPath() }

func (a *app) success(data any, human func(io.Writer) error, warnings []cliresult.Warning) error {
	if a.json {
		if err := cliresult.WriteSuccess(a.out, data, warnings); err != nil {
			return cliresult.IO("write JSON output", err)
		}
		return nil
	}
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(a.errOut, "warning: %s\n", warning.Message); err != nil {
			return cliresult.IO("write warning", err)
		}
	}
	if !a.quiet && human != nil {
		if err := human(a.out); err != nil {
			return cliresult.IO("write command output", err)
		}
	}
	return nil
}
func (a *app) confirm(prompt string) error {
	t, err := a.openTerminal()
	if err != nil {
		return cliresult.IO("open controlling terminal", err)
	}
	defer t.Close()
	value, err := readTerminalLine(t, prompt)
	if err != nil {
		return cliresult.IO("read confirmation", err)
	}
	if !strings.EqualFold(value, "y") && !strings.EqualFold(value, "yes") {
		return cliresult.Declined("security confirmation declined")
	}
	return nil
}
func readTerminalLine(t proclamation.Terminal, prompt string) (string, error) {
	if _, err := t.Write([]byte(prompt)); err != nil {
		return "", err
	}
	// Terminal only exposes password reads; confirmations intentionally use no-echo too.
	value, err := t.ReadPassword(nil)
	if err != nil {
		return "", err
	}
	defer clear(value)
	return strings.TrimSpace(string(value)), nil
}
func (a *app) stdoutTerminal() bool { return a.outputIsTerminal != nil && a.outputIsTerminal(a.out) }
func (a *app) revealConfirmation() error {
	if !a.stdoutTerminal() {
		return nil
	}
	const warning = "WARNING: decrypted secrets will be written to this terminal and may remain visible in terminal history."
	t, err := a.openTerminal()
	if err != nil {
		return cliresult.IO("open controlling terminal", err)
	}
	defer t.Close()
	value, err := readTerminalLine(t, warning+"\nReveal secrets to terminal? [y/N]: ")
	if err != nil {
		return cliresult.IO("read reveal confirmation", err)
	}
	if !strings.EqualFold(value, "y") && !strings.EqualFold(value, "yes") {
		return cliresult.Declined("security confirmation declined")
	}
	if _, err := fmt.Fprintln(a.errOut, warning); err != nil {
		return cliresult.IO("write reveal warning", err)
	}
	return nil
}
func (a *app) context() context.Context { return context.Background() }
func (a *app) prepareCommand() error {
	if a.securityPrepared {
		return nil
	}
	if err := a.establishSecurityControls(); err != nil {
		return err
	}
	if err := gitruntime.Initialize(); err != nil {
		return cliresult.New("internal_error", "cannot initialize in-process Git runtime", cliresult.EXSoftware, false, err)
	}
	if a.guardians == nil {
		if a.newGuardianStore == nil {
			return cliresult.New("security_control_failed", "guardian provider initialization is unavailable", cliresult.EXSoftware, false, nil)
		}
		a.guardians = a.newGuardianStore()
	}
	a.securityPrepared = true
	return nil
}
func (a *app) establishSecurityControls() error {
	if a.disableCoreDumps == nil {
		return cliresult.New("security_control_failed", "macOS core-dump control is unavailable", cliresult.EXSoftware, false, nil)
	}
	if err := a.disableCoreDumps(); err != nil {
		return cliresult.New("security_control_failed", "cannot establish macOS core-dump control", cliresult.EXSoftware, false, err)
	}
	return nil
}

// retained for tests using simple line-oriented fake terminals.
type readerTerminal struct {
	io.Reader
	io.Writer
}

func (r readerTerminal) ReadPassword(_ []byte) ([]byte, error) {
	line, err := bufio.NewReader(r.Reader).ReadString('\n')
	return []byte(strings.TrimSpace(line)), err
}
func (readerTerminal) Close() error { return nil }
