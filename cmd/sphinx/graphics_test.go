package main

import (
	"bytes"
	"fmt"
	"image/png"
	"io"
	"strings"
	"testing"
)

func TestKittyGraphicsSupportedRequiresMatchingSuccessfulQuery(t *testing.T) {
	matching := fmt.Sprintf("noise\x1b_Gi=%d;OK\x1b\\tail", kittyGraphicsImageID)
	if !kittyGraphicsSupported([]byte(matching)) {
		t.Fatal("matching Kitty graphics response was rejected")
	}
	for _, response := range []string{
		"",
		fmt.Sprintf("\x1b_Gi=%d;EINVAL\x1b\\", kittyGraphicsImageID),
		"\x1b_Gi=12;OK\x1b\\",
		fmt.Sprintf("\x1b_Gi=%d;OK", kittyGraphicsImageID),
	} {
		if kittyGraphicsSupported([]byte(response)) {
			t.Fatalf("invalid Kitty graphics response accepted: %q", response)
		}
	}
}

func TestEmbeddedSphinxAndKittyTransmission(t *testing.T) {
	config, err := png.DecodeConfig(bytes.NewReader(sphinxPNG))
	if err != nil {
		t.Fatal(err)
	}
	if config.Width != 480 || config.Height != 220 {
		t.Fatalf("sphinx image dimensions = %dx%d", config.Width, config.Height)
	}

	var out bytes.Buffer
	if !writeKittyImage(&out, sphinxPNG) {
		t.Fatal("Kitty image transmission failed")
	}
	transmission := out.String()
	prefix := fmt.Sprintf("\x1b_Ga=T,f=100,t=d,i=%d,q=2,c=%d,r=%d,C=1,m=1;", kittyGraphicsImageID, kittyGraphicsColumns, kittyGraphicsRows)
	if !strings.HasPrefix(transmission, prefix) {
		t.Fatalf("transmission prefix = %q", transmission[:min(len(transmission), len(prefix))])
	}
	if !strings.Contains(transmission, "\x1b\\\x1b_Gm=0;") {
		t.Fatal("chunked transmission terminator missing")
	}
	if !strings.HasSuffix(transmission, "\r"+strings.Repeat("\n", kittyGraphicsRows)) {
		t.Fatal("transmission does not reserve image rows")
	}
}

func TestRootHelpRendersGraphicButSubcommandHelpDoesNot(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	var out bytes.Buffer
	a, err := newApp(&out, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a.outputIsTerminal = func(w io.Writer) bool { return w == io.Writer(&out) }
	a.renderHelpGraphic = func(w io.Writer) bool {
		_, _ = io.WriteString(w, "<graphic>\n")
		return true
	}
	a.detectHelpBackground = func(io.Writer) helpBackground { return helpBackgroundDark }
	root := newRootCommand(a)
	root.InitDefaultHelpCmd()
	root.SetOut(&out)
	if err := root.Help(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "<graphic>\n") || !strings.Contains(out.String(), "Manage signed tombs") {
		t.Fatalf("root help did not start with graphic: %q", out.String())
	}

	out.Reset()
	artifact, _, err := root.Find([]string{"artifact"})
	if err != nil {
		t.Fatal(err)
	}
	artifact.SetOut(&out)
	if err := artifact.Help(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<graphic>") {
		t.Fatal("subcommand help rendered the root graphic")
	}
}

func TestRootGraphicRequiresEligibleTerminalOutput(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	var out bytes.Buffer
	calls := 0
	a := &app{
		outputIsTerminal: func(io.Writer) bool { return true },
		renderHelpGraphic: func(w io.Writer) bool {
			calls++
			_, _ = io.WriteString(w, "graphic")
			return true
		},
	}
	a.writeRootGraphic(&out)
	if calls != 1 || out.String() != "graphic" {
		t.Fatalf("calls=%d output=%q", calls, out.String())
	}

	for name, configure := range map[string]func(*app){
		"JSON":     func(a *app) { a.json = true },
		"quiet":    func(a *app) { a.quiet = true },
		"no color": func(a *app) { a.noColor = true },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *a
			configure(&candidate)
			candidate.writeRootGraphic(io.Discard)
			if calls != 1 {
				t.Fatalf("renderer called for %s output", name)
			}
		})
	}

	t.Setenv("TERM", "dumb")
	a.writeRootGraphic(io.Discard)
	if calls != 1 {
		t.Fatal("renderer called for TERM=dumb")
	}
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "1")
	a.writeRootGraphic(io.Discard)
	if calls != 1 {
		t.Fatal("renderer called with NO_COLOR")
	}
}
