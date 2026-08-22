package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	kittyGraphicsImageID = 1937010547
	kittyGraphicsColumns = 36
	kittyGraphicsRows    = 9
)

//go:embed assets/sphinx.png
var sphinxPNG []byte

func (a *app) writeRootGraphic(out io.Writer) {
	if a.json || a.quiet || a.noColor || noColorEnvironment() || os.Getenv("TERM") == "dumb" || a.outputIsTerminal == nil || !a.outputIsTerminal(out) || a.renderHelpGraphic == nil {
		return
	}
	a.renderHelpGraphic(out)
}

func renderKittySphinx(out io.Writer) bool {
	if !probeKittyGraphics(out) {
		return false
	}
	return writeKittyImage(out, sphinxPNG)
}

func probeKittyGraphics(out io.Writer) bool {
	query := fmt.Sprintf("\x1b_Gi=%d,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\", kittyGraphicsImageID)
	return queryTerminal(out, query, kittyGraphicsSupported)
}

func kittyGraphicsSupported(response []byte) bool {
	prefix := []byte("\x1b_G")
	suffix := []byte("\x1b\\")
	expectedID := []byte(fmt.Sprintf("i=%d", kittyGraphicsImageID))
	for rest := response; ; {
		start := bytes.Index(rest, prefix)
		if start < 0 {
			return false
		}
		rest = rest[start+len(prefix):]
		end := bytes.Index(rest, suffix)
		if end < 0 {
			return false
		}
		frame := rest[:end]
		rest = rest[end+len(suffix):]
		control, payload, found := bytes.Cut(frame, []byte(";"))
		if !found || !bytes.Equal(payload, []byte("OK")) {
			continue
		}
		for _, field := range bytes.Split(control, []byte(",")) {
			if bytes.Equal(field, expectedID) {
				return true
			}
		}
	}
}

func writeKittyImage(out io.Writer, png []byte) bool {
	const chunkSize = 4096
	encoded := base64.StdEncoding.EncodeToString(png)
	for offset := 0; offset < len(encoded); offset += chunkSize {
		end := min(offset+chunkSize, len(encoded))
		more := 0
		if end < len(encoded) {
			more = 1
		}
		var command bytes.Buffer
		if offset == 0 {
			fmt.Fprintf(&command, "\x1b_Ga=T,f=100,t=d,i=%d,q=2,c=%d,r=%d,C=1,m=%d;", kittyGraphicsImageID, kittyGraphicsColumns, kittyGraphicsRows, more)
		} else {
			fmt.Fprintf(&command, "\x1b_Gm=%d;", more)
		}
		command.WriteString(encoded[offset:end])
		command.WriteString("\x1b\\")
		if _, err := out.Write(command.Bytes()); err != nil {
			return false
		}
	}
	_, err := io.WriteString(out, "\r"+strings.Repeat("\n", kittyGraphicsRows))
	return err == nil
}
