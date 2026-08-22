package main

import (
	"io"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const terminalQueryTimeout = 100 * time.Millisecond

func queryTerminal(out io.Writer, query string, accept func([]byte) bool) bool {
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
	if _, err := io.WriteString(out, query); err != nil {
		return false
	}

	deadline := time.Now().Add(terminalQueryTimeout)
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
			if accept(response) {
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
