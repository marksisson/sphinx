package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type helpBackground uint8

const (
	helpBackgroundUnknown helpBackground = iota
	helpBackgroundDark
	helpBackgroundLight
)

const ansiReset = "\x1b[0m"

type helpPalette struct {
	heading string
	accent  string
	copy    string
}

var (
	// Colors are sampled from the embedded image and adjusted for contrast.
	darkHelpPalette = helpPalette{
		heading: "\x1b[1;38;2;232;177;69m",
		accent:  "\x1b[1;38;2;41;190;198m",
		copy:    "\x1b[38;2;248;231;181m",
	}
	lightHelpPalette = helpPalette{
		heading: "\x1b[1;38;2;0;48;61m",
		accent:  "\x1b[1;38;2;0;110;125m",
		copy:    "\x1b[38;2;145;94;25m",
	}
)

func (a *app) writeHelpText(out io.Writer, text string) error {
	if !a.colorHelpEnabled(out) {
		_, err := io.WriteString(out, text)
		return err
	}
	background := helpBackgroundUnknown
	if a.detectHelpBackground != nil {
		background = a.detectHelpBackground(out)
	}
	palette := darkHelpPalette
	if background == helpBackgroundLight {
		palette = lightHelpPalette
	}
	_, err := io.WriteString(out, colorizeHelp(text, palette))
	return err
}

func (a *app) colorHelpEnabled(out io.Writer) bool {
	if a.json || a.quiet || a.noColor || os.Getenv("TERM") == "dumb" || a.outputIsTerminal == nil || !a.outputIsTerminal(out) {
		return false
	}
	return !noColorEnvironment()
}

func noColorEnvironment() bool {
	noColor, present := os.LookupEnv("NO_COLOR")
	return present && noColor != ""
}

func detectTerminalBackground(out io.Writer) helpBackground {
	background := helpBackgroundUnknown
	queryTerminal(out, "\x1b]11;?\x1b\\", func(response []byte) bool {
		parsed, ok := parseTerminalBackground(response)
		if ok {
			background = parsed
		}
		return ok
	})
	return background
}

func parseTerminalBackground(response []byte) (helpBackground, bool) {
	prefix := []byte("\x1b]11;rgb:")
	start := bytes.Index(response, prefix)
	if start < 0 {
		return helpBackgroundUnknown, false
	}
	value := response[start+len(prefix):]
	end := len(value)
	if bell := bytes.IndexByte(value, '\a'); bell >= 0 && bell < end {
		end = bell
	}
	if stringTerminator := bytes.Index(value, []byte("\x1b\\")); stringTerminator >= 0 && stringTerminator < end {
		end = stringTerminator
	}
	if end == len(value) {
		return helpBackgroundUnknown, false
	}
	components := bytes.Split(value[:end], []byte("/"))
	if len(components) != 3 {
		return helpBackgroundUnknown, false
	}
	rgb := [3]float64{}
	for index, component := range components {
		if len(component) == 0 || len(component) > 4 {
			return helpBackgroundUnknown, false
		}
		parsed, err := strconv.ParseUint(string(component), 16, 16)
		if err != nil {
			return helpBackgroundUnknown, false
		}
		maximum := float64(uint64(1)<<(4*len(component)) - 1)
		rgb[index] = float64(parsed) / maximum
	}
	luminance := 0.299*rgb[0] + 0.587*rgb[1] + 0.114*rgb[2]
	if luminance >= 0.5 {
		return helpBackgroundLight, true
	}
	return helpBackgroundDark, true
}

func colorizeHelp(text string, palette helpPalette) string {
	lines := strings.SplitAfter(text, "\n")
	section := ""
	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\n")
		newline := raw[len(line):]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			section = ""
			continue
		}
		if line == trimmed && strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			lines[index] = paint(palette.heading, line) + newline
			continue
		}
		if strings.HasPrefix(line, "Use \"") {
			lines[index] = paintQuoted(palette.accent, line) + newline
			continue
		}
		switch section {
		case "Usage":
			lines[index] = paintIndented(palette.accent, line) + newline
		case "Available Commands", "Additional Commands", "Additional help topics":
			lines[index] = paintFirstToken(palette.accent, line) + newline
		case "Flags", "Global Flags":
			lines[index] = paintFlagSpec(palette.accent, line) + newline
		default:
			if section == "" {
				lines[index] = paint(palette.copy, line) + newline
			}
		}
	}
	return strings.Join(lines, "")
}

func paint(color, value string) string {
	if value == "" {
		return value
	}
	return color + value + ansiReset
}

func paintIndented(color, line string) string {
	leading := len(line) - len(strings.TrimLeft(line, " \t"))
	trailing := len(strings.TrimRight(line, " \t"))
	if leading >= trailing {
		return line
	}
	return line[:leading] + paint(color, line[leading:trailing]) + line[trailing:]
}

func paintFirstToken(color, line string) string {
	leading := len(line) - len(strings.TrimLeft(line, " \t"))
	end := leading
	for end < len(line) && line[end] != ' ' && line[end] != '\t' {
		end++
	}
	if end == leading {
		return line
	}
	return line[:leading] + paint(color, line[leading:end]) + line[end:]
}

func paintFlagSpec(color, line string) string {
	leading := len(line) - len(strings.TrimLeft(line, " \t"))
	boundary := -1
	for index := leading; index < len(line); {
		if line[index] != ' ' && line[index] != '\t' {
			index++
			continue
		}
		end := index
		for end < len(line) && (line[end] == ' ' || line[end] == '\t') {
			end++
		}
		if end-index >= 3 {
			boundary = index
			break
		}
		index = end
	}
	if boundary <= leading {
		return line
	}
	return line[:leading] + paint(color, line[leading:boundary]) + line[boundary:]
}

func paintQuoted(color, line string) string {
	start := strings.IndexByte(line, '"')
	end := strings.LastIndexByte(line, '"')
	if start < 0 || end <= start {
		return line
	}
	return fmt.Sprintf("%s\"%s\"%s", line[:start], paint(color, line[start+1:end]), line[end+1:])
}
