package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestParseTerminalBackground(t *testing.T) {
	for name, test := range map[string]struct {
		response string
		want     helpBackground
		ok       bool
	}{
		"dark ST":   {response: "noise\x1b]11;rgb:0000/1111/2222\x1b\\", want: helpBackgroundDark, ok: true},
		"light BEL": {response: "\x1b]11;rgb:ffff/eeee/dddd\a", want: helpBackgroundLight, ok: true},
		"short RGB": {response: "\x1b]11;rgb:0/f/0\x1b\\", want: helpBackgroundLight, ok: true},
		"partial":   {response: "\x1b]11;rgb:ffff/ffff/ffff", want: helpBackgroundUnknown, ok: false},
		"malformed": {response: "\x1b]11;rgb:nope/ffff/ffff\a", want: helpBackgroundUnknown, ok: false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := parseTerminalBackground([]byte(test.response))
			if got != test.want || ok != test.ok {
				t.Fatalf("background=%v ok=%v, want %v/%v", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestColorizeHelpPreservesTextAndUsesSelectedPalette(t *testing.T) {
	plain := "Manage signed tombs and reveal authorized secrets\n\nUsage:\n  sphinx [flags]\n\nAvailable Commands:\n  artifact     Create artifacts\n\nFlags:\n      --json   emit JSON\n\nUse \"sphinx [command] --help\" for more information.\n"
	for name, palette := range map[string]helpPalette{"dark": darkHelpPalette, "light": lightHelpPalette} {
		t.Run(name, func(t *testing.T) {
			colored := colorizeHelp(plain, palette)
			if stripHelpColors(colored) != plain {
				t.Fatalf("color changed help text:\n%q", colored)
			}
			if !strings.Contains(colored, palette.heading+"Usage:"+ansiReset) {
				t.Fatal("heading color missing")
			}
			if !strings.Contains(colored, palette.accent+"artifact"+ansiReset) {
				t.Fatal("command color missing")
			}
			if !strings.Contains(colored, palette.copy+"Manage signed tombs") {
				t.Fatal("description color missing")
			}
		})
	}
}

func TestWriteHelpTextColorEligibilityAndLightMode(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	var out bytes.Buffer
	a := &app{
		outputIsTerminal:     func(io.Writer) bool { return true },
		detectHelpBackground: func(io.Writer) helpBackground { return helpBackgroundLight },
	}
	plain := "Usage:\n  sphinx [command]\n"
	if err := a.writeHelpText(&out, plain); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), lightHelpPalette.heading) || stripHelpColors(out.String()) != plain {
		t.Fatalf("light help output = %q", out.String())
	}

	for name, configure := range map[string]func(*app){
		"JSON":     func(a *app) { a.json = true },
		"quiet":    func(a *app) { a.quiet = true },
		"no color": func(a *app) { a.noColor = true },
		"redirect": func(a *app) { a.outputIsTerminal = func(io.Writer) bool { return false } },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *a
			configure(&candidate)
			var output bytes.Buffer
			if err := candidate.writeHelpText(&output, plain); err != nil {
				t.Fatal(err)
			}
			if output.String() != plain {
				t.Fatalf("decorated ineligible help: %q", output.String())
			}
		})
	}

	t.Setenv("NO_COLOR", "1")
	out.Reset()
	if err := a.writeHelpText(&out, plain); err != nil {
		t.Fatal(err)
	}
	if out.String() != plain {
		t.Fatalf("NO_COLOR output = %q", out.String())
	}
}

func stripHelpColors(value string) string {
	for _, palette := range []helpPalette{darkHelpPalette, lightHelpPalette} {
		value = strings.ReplaceAll(value, palette.heading, "")
		value = strings.ReplaceAll(value, palette.accent, "")
		value = strings.ReplaceAll(value, palette.copy, "")
	}
	return strings.ReplaceAll(value, ansiReset, "")
}
