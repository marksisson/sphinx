package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	kittyGraphicsImageID = 1937010547
	kittyGraphicsColumns = 36
	kittyGraphicsRows    = 9
	kittyGraphicsTimeout = 100 * time.Millisecond
)

//go:embed assets/sphinx.png
var sphinxPNG []byte

func (a *app) writeRootGraphic(out io.Writer) {
	if a.json || a.quiet || a.noColor || os.Getenv("TERM") == "dumb" || a.outputIsTerminal == nil || !a.outputIsTerminal(out) || a.renderHelpGraphic == nil {
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
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	state, err := term.MakeRaw(fd)
	if err != nil {
		return false
	}
	defer func() { _ = term.Restore(fd, state) }()
	if err := unix.SetNonblock(fd, true); err != nil {
		return false
	}

	query := fmt.Sprintf("\x1b_Gi=%d,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\", kittyGraphicsImageID)
	if _, err := io.WriteString(out, query); err != nil {
		return false
	}

	deadline := time.Now().Add(kittyGraphicsTimeout)
	response := make([]byte, 0, 256)
	buffer := make([]byte, 256)
	defer func() {
		clear(response)
		clear(buffer)
	}()
	for time.Now().Before(deadline) && len(response) < 4096 {
		n, readErr := unix.Read(fd, buffer)
		if n > 0 {
			response = append(response, buffer[:n]...)
			if kittyGraphicsSupported(response) {
				return true
			}
		}
		if readErr != nil && readErr != unix.EAGAIN && readErr != unix.EWOULDBLOCK && readErr != unix.EINTR {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
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
