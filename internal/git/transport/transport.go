// Package transport owns Sphinx's noninteractive Git transport policy.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v6/plumbing/client"
	gogittransport "github.com/go-git/go-git/v6/plumbing/transport"
	gogitssh "github.com/go-git/go-git/v6/plumbing/transport/ssh"
	gogitsshagent "github.com/go-git/go-git/v6/plumbing/transport/ssh/sshagent"
	"github.com/kevinburke/ssh_config"
	gossh "golang.org/x/crypto/ssh"
)

// Session contains options for one go-git operation and owns any transport
// resources opened while constructing those options.
type Session struct {
	Options []client.Option
	Network bool
	closers []io.Closer
}

// Open validates a canonical repository URL and creates explicit transport
// policy. Local paths use no network transport options.
func Open(rawURL string) (*Session, error) {
	return open(rawURL, nil)
}

func open(rawURL string, roots *x509.CertPool) (*Session, error) {
	if filepath.IsAbs(rawURL) {
		return &Session{}, nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Git transport URL")
	}
	if parsed.Fragment != "" || parsed.RawQuery != "" {
		return nil, fmt.Errorf("Git transport URL contains unsupported components")
	}
	if parsed.User != nil {
		if _, present := parsed.User.Password(); present || parsed.Scheme != "ssh" || parsed.User.Username() != "git" {
			return nil, fmt.Errorf("Git transport URL contains unsupported credentials")
		}
	}
	switch parsed.Scheme {
	case "https":
		httpClient := newHTTPSClient(roots)
		return &Session{
			Network: true,
			Options: []client.Option{
				client.WithHTTPClient(httpClient),
				client.WithRedirectPolicy(client.FollowInitialRedirects),
			},
			closers: []io.Closer{httpClient.Transport.(*smartHTTPSRoundTripper)},
		}, nil
	case "ssh":
		return openSSH(parsed)
	default:
		return nil, fmt.Errorf("unsupported Git transport scheme")
	}
}

func newHTTPSClient(roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	return &http.Client{Transport: &smartHTTPSRoundTripper{transport: transport}, CheckRedirect: secureRedirect}
}

type smartHTTPSRoundTripper struct{ transport *http.Transport }

func (t *smartHTTPSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if (response.StatusCode < 300 || response.StatusCode >= 400) && request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/info/refs") && request.URL.Query().Get("service") == "git-upload-pack" {
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
		if contentType != "application/x-git-upload-pack-advertisement" {
			_ = response.Body.Close()
			return nil, fmt.Errorf("Git HTTPS endpoint does not support smart protocol")
		}
	}
	return response, nil
}

func (t *smartHTTPSRoundTripper) Close() error {
	t.transport.CloseIdleConnections()
	return nil
}

func secureRedirect(request *http.Request, via []*http.Request) error {
	if request.URL == nil || request.URL.Scheme != "https" {
		return fmt.Errorf("Git HTTPS redirect uses an unsupported scheme")
	}
	if len(via) >= 10 {
		return fmt.Errorf("Git HTTPS redirect limit exceeded")
	}
	if len(via) != 0 && !sameAuthority(via[len(via)-1].URL, request.URL) {
		request.Header.Del("Authorization")
		request.Header.Del("Proxy-Authorization")
		request.Header.Del("Cookie")
	}
	return nil
}

func sameAuthority(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func openSSH(parsed *url.URL) (*Session, error) {
	// sshagent.New reads SSH_AUTH_SOCK; no identity file or password source is consulted.
	username := "git"
	if parsed.User != nil && parsed.User.Username() != "" {
		username = parsed.User.Username()
	}
	agentClient, connection, err := gogitsshagent.New()
	if err != nil {
		return nil, fmt.Errorf("SSH agent is unavailable")
	}
	knownHosts, err := standardKnownHostsFiles()
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	hostKeyCallback, err := gogitssh.NewKnownHostsCallback(knownHosts...)
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("SSH known-host verification is unavailable")
	}
	authentication := &gogitssh.PublicKeysCallback{User: username, Callback: agentClient.Signers}
	authentication.HostKeyCallback = hostKeyCallback

	// An empty UserSettings prevents go-git from reading user/system SSH
	// routing, identity, proxy, or command directives. Host, user, and port
	// therefore come only from the canonical URL.
	emptySettings := &ssh_config.UserSettings{}
	dialer := &sshOperationDialer{}
	sshTransport := gogitssh.NewTransport(gogitssh.Options{
		ClientConfig: func(ctx context.Context, request *gogittransport.Request) (*gossh.ClientConfig, error) {
			dialer.setContext(ctx)
			return authentication.ClientConfig(ctx, request)
		},
		DialContext: dialer.dialContext,
		UserSettings: func(context.Context, *gogittransport.Request) (*ssh_config.UserSettings, error) {
			return emptySettings, nil
		},
	})
	return &Session{
		Network: true,
		Options: []client.Option{client.WithTransport("ssh", sshTransport)},
		closers: []io.Closer{connection},
	}, nil
}

type sshOperationDialer struct {
	mu  sync.Mutex
	ctx context.Context
}

func (d *sshOperationDialer) setContext(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ctx = ctx
}

func (d *sshOperationDialer) dialContext(fallback context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	ctx := d.ctx
	d.mu.Unlock()
	if ctx == nil {
		ctx = fallback
	}
	return contextBoundDial(ctx, network, address)
}

func contextBoundDial(ctx context.Context, network, address string) (net.Conn, error) {
	connection, err := (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	wrapped := &contextConnection{Conn: connection, done: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = wrapped.Close()
		case <-wrapped.done:
		}
	}()
	return wrapped, nil
}

type contextConnection struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *contextConnection) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		err = c.Conn.Close()
	})
	return err
}

func standardKnownHostsFiles() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve SSH known-host location")
	}
	candidates := []string{filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"}
	files := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		information, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("SSH known-host source is unsafe")
		}
		files = append(files, candidate)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("SSH known-host verification is unavailable")
	}
	return files, nil
}

// Close releases SSH-agent and idle HTTP resources. It is safe to call more
// than once.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var first error
	for index := len(s.closers) - 1; index >= 0; index-- {
		if s.closers[index] == nil {
			continue
		}
		if err := s.closers[index].Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
			first = err
		}
		s.closers[index] = nil
	}
	return first
}

// SafeError returns a stable transport diagnostic without embedding a URL,
// user name, socket path, host key, credential, or upstream error text.
func SafeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("Git transport %s canceled", operation)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("Git transport %s timed out", operation)
	}
	text := strings.ToLower(err.Error())
	classification := "failed"
	switch {
	case strings.Contains(text, "certificate"), strings.Contains(text, "tls"):
		classification = "failed TLS verification"
	case strings.Contains(text, "knownhosts"), strings.Contains(text, "known host"), strings.Contains(text, "host key"):
		classification = "failed SSH host verification"
	case strings.Contains(text, "authentication"), strings.Contains(text, "unable to authenticate"), strings.Contains(text, "ssh agent"):
		classification = "failed authentication"
	case strings.Contains(text, "connection refused"), strings.Contains(text, "no such host"), strings.Contains(text, "network is unreachable"):
		classification = "is unavailable"
	case strings.Contains(text, "protocol"), strings.Contains(text, "pkt-line"), strings.Contains(text, "malformed"):
		classification = "returned an invalid Git protocol response"
	}
	return fmt.Errorf("Git transport %s %s", operation, classification)
}
