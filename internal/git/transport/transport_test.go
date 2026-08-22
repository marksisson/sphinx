package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestOpenAcceptsOnlySupportedCanonicalTransportURLs(t *testing.T) {
	local := filepath.Join(t.TempDir(), "repository")
	if session, err := Open(local); err != nil || session.Network {
		t.Fatalf("local session = %#v, %v", session, err)
	}
	for _, rawURL := range []string{
		"http://example.invalid/repository.git",
		"git://example.invalid/repository.git",
		"file:///tmp/repository.git",
		"https://user:secret@example.invalid/repository.git",
		"ssh://root@example.invalid/repository.git",
		"https://example.invalid/repository.git?token=secret",
		"https://example.invalid/repository.git#fragment",
	} {
		if _, err := Open(rawURL); err == nil {
			t.Errorf("Open(%q) unexpectedly succeeded", rawURL)
		}
	}
}

func TestHTTPSRequiresCertificateVerificationAndIgnoresProxyEnvironment(t *testing.T) {
	server := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()

	if _, err := newHTTPSClient(nil).Get(server.URL); err == nil {
		t.Fatal("HTTPS client trusted an unknown certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	response, err := newHTTPSClient(roots).Get(server.URL)
	if err != nil {
		t.Fatalf("verified direct HTTPS request: %v", err)
	}
	_ = response.Body.Close()
}

func TestHTTPSRejectsDumbGitAdvertisement(t *testing.T) {
	server := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "dumb advertisement")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if _, err := newHTTPSClient(roots).Get(server.URL + "/repository.git/info/refs?service=git-upload-pack"); err == nil {
		t.Fatal("dumb HTTPS advertisement was accepted")
	}
}

func TestHTTPSRedirectStripsCrossAuthorityHeadersAndRejectsDowngrade(t *testing.T) {
	seen := make(chan http.Header, 1)
	backend := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen <- request.Header.Clone()
		writer.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	frontend := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, backend.URL+request.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer frontend.Close()
	roots := x509.NewCertPool()
	roots.AddCert(frontend.Certificate())
	roots.AddCert(backend.Certificate())
	request, _ := http.NewRequest(http.MethodGet, frontend.URL+"/repository.git/info/refs?service=git-upload-pack", nil)
	request.Header.Set("Authorization", "Bearer transport-secret")
	request.Header.Set("Proxy-Authorization", "Basic proxy-secret")
	request.Header.Set("Cookie", "session=cookie-secret")
	response, err := newHTTPSClient(roots).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	headers := <-seen
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		if headers.Get(name) != "" {
			t.Fatalf("cross-authority redirect forwarded %s", name)
		}
	}

	downgrade, _ := http.NewRequest(http.MethodGet, "http://example.invalid/target", nil)
	if err := secureRedirect(downgrade, []*http.Request{request}); err == nil {
		t.Fatal("HTTPS downgrade redirect was accepted")
	}
}

func TestHTTPSContextCancellationIsPrompt(t *testing.T) {
	server := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	started := time.Now()
	if _, err := newHTTPSClient(roots).Do(request); err == nil {
		t.Fatal("cancelled HTTPS request succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("HTTPS cancellation took %s", elapsed)
	}
}

func TestSSHDialConnectionClosesWhenContextIsCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	connection, err := contextBoundDial(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	defer serverConnection.Close()
	started := time.Now()
	if _, err := connection.Read(make([]byte, 1)); err == nil {
		t.Fatal("canceled SSH connection remained readable")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SSH cancellation took %s", elapsed)
	}
}

func TestStandardKnownHostsIgnoresOverrideAndRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(directory, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("example.invalid ssh-ed25519 AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_KNOWN_HOSTS", filepath.Join(t.TempDir(), "hostile"))
	files, err := standardKnownHostsFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 || files[0] != knownHosts {
		t.Fatalf("known-host sources = %#v", files)
	}
	if err := os.Remove(knownHosts); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "target"), knownHosts); err != nil {
		t.Fatal(err)
	}
	if _, err := standardKnownHostsFiles(); err == nil {
		t.Fatal("symlinked known-host source was accepted")
	}
}

func TestSSHSessionOwnsAndClosesAgentConnection(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{"example.invalid"}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(filepath.Join(sshDirectory, "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	agentResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			agentResult <- err
			return
		}
		defer connection.Close()
		agentResult <- agent.ServeAgent(agent.NewKeyring(), connection)
	}()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", socket)
	session, err := Open("ssh://git@example.invalid/repository.git")
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-agentResult:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("agent close result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH session did not close its agent connection")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	closer := &countingCloser{}
	session := &Session{closers: []io.Closer{closer}}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if closer.calls != 1 {
		t.Fatalf("closer called %d times", closer.calls)
	}
}

func TestSafeErrorDoesNotLeakUpstreamDetails(t *testing.T) {
	secret := "ssh://git@private.example.invalid/secret.git?token=transport-secret"
	for _, err := range []error{
		errors.New("unable to authenticate " + secret),
		errors.New("x509 certificate error for " + secret),
		context.Canceled,
		context.DeadlineExceeded,
	} {
		message := SafeError("advertisement", err).Error()
		for _, forbidden := range []string{"private.example.invalid", "secret.git", "transport-secret", "git@"} {
			if strings.Contains(message, forbidden) {
				t.Fatalf("safe error leaked %q: %s", forbidden, message)
			}
		}
	}
}

func newQuietTLSServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	return server
}

type countingCloser struct{ calls int }

func (c *countingCloser) Close() error {
	c.calls++
	return nil
}
