package differential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	serverssh "github.com/gliderlabs/ssh"
	git "github.com/go-git/go-git/v6"
	gogitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/storage/memory"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	gittransport "github.com/marksisson/sphinx/internal/git/transport"
	"github.com/marksisson/sphinx/internal/locator"
	testgit "github.com/marksisson/sphinx/internal/testgit"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSmartSSHAgentAdvertisementMatchesNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	bare := filepath.Join(t.TempDir(), "remote.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, bare)
	clientSigner, clientPrivate := newSSHSigner(t)
	hostSigner, _ := newSSHSigner(t)
	agentSocket := startSSHAgent(t, clientPrivate)
	t.Setenv("SSH_AUTH_SOCK", agentSocket)
	address := startGitSSHServer(t, bare, hostSigner, clientSigner.PublicKey())
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	knownHostsFile := filepath.Join(sshDirectory, "known_hosts")
	line := knownhosts.Line([]string{address}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sphinx must ignore routing and command directives even when they match.
	configuration := "Host 127.0.0.1\n  HostName hostile.invalid\n  Port 1\n  ProxyCommand false\n  IdentityFile /does/not/exist\n"
	if err := os.WriteFile(filepath.Join(sshDirectory, "config"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteURL := "ssh://git@" + address + "/remote.git"

	for _, selector := range []string{"", "lightweight", "annotated"} {
		want, err := nativeSSHList(context.Background(), remoteURL, selector, knownHostsFile)
		if err != nil {
			t.Fatalf("native SSH selector %q: %v", selector, err)
		}
		got, err := goGitSSHList(context.Background(), remoteURL, selector)
		if err != nil {
			t.Fatalf("go-git SSH selector %q: %v", selector, err)
		}
		if got != want {
			t.Fatalf("SSH selector %q disagreement: native=%s go-git=%s", selector, want, got)
		}
	}

	// Exercise production remote resolution and mirror materialization while no
	// Git executable can be discovered by the Sphinx process.
	originalPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", ""); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Setenv("PATH", originalPath) }()
	reference := locator.Locator{Type: locator.TypeGit, URL: remoteURL}
	resolved, resolveErr := gitresource.ResolveCommit(context.Background(), reference)
	var materializeErr error
	if resolveErr == nil {
		_, materializeErr = (gitresource.Materializer{CacheRoot: filepath.Join(t.TempDir(), "cache")}).Materialize(context.Background(), reference, resolved)
	}
	if err := os.Setenv("PATH", originalPath); err != nil {
		t.Fatal(err)
	}
	if resolveErr != nil || resolved != fixture.secondCommit || materializeErr != nil {
		t.Fatalf("empty-PATH remote operation resolved=%q want=%q resolve=%v materialize=%v", resolved, fixture.secondCommit, resolveErr, materializeErr)
	}

	wrongSigner, _ := newSSHSigner(t)
	wrongKnownHosts := filepath.Join(t.TempDir(), "wrong_known_hosts")
	if err := os.WriteFile(wrongKnownHosts, []byte(knownhosts.Line([]string{address}, wrongSigner.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nativeSSHList(context.Background(), remoteURL, "", wrongKnownHosts); err == nil {
		t.Fatal("native Git accepted a changed SSH host key")
	}
	if err := os.WriteFile(knownHostsFile, []byte(knownhosts.Line([]string{address}, wrongSigner.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := goGitSSHList(context.Background(), remoteURL, ""); err == nil {
		t.Fatal("go-git accepted a changed SSH host key")
	}
}

func nativeSSHList(ctx context.Context, remoteURL, selector, knownHostsFile string) (string, error) {
	patterns := []string{"HEAD"}
	if selector != "" {
		patterns = []string{"refs/heads/" + selector, "refs/tags/" + selector, "refs/tags/" + selector + "^{}"}
	}
	arguments := append([]string{"ls-remote", "--", remoteURL}, patterns...)
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Env = append(testgit.Environment(),
		"GIT_SSH_COMMAND=ssh -F /dev/null -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+knownHostsFile,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("native SSH advertisement: %w: %s", err, output)
	}
	return resolveAdvertisedReferences(output, selector)
}

func goGitSSHList(ctx context.Context, remoteURL, selector string) (string, error) {
	session, err := gittransport.Open(remoteURL)
	if err != nil {
		return "", err
	}
	defer session.Close()
	remote := git.NewRemote(memory.NewStorage(), &gogitconfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	references, err := remote.ListContext(ctx, &git.ListOptions{
		PeelingOption: git.AppendPeeled,
		ClientOptions: session.Options,
	})
	if err != nil {
		return "", err
	}
	byName := make(map[plumbing.ReferenceName]*plumbing.Reference, len(references))
	for _, reference := range references {
		byName[reference.Name()] = reference
	}
	var advertisement bytes.Buffer
	for _, reference := range references {
		hash := reference.Hash()
		if reference.Type() == plumbing.SymbolicReference {
			target, exists := byName[reference.Target()]
			if !exists {
				return "", fmt.Errorf("symbolic target is missing")
			}
			hash = target.Hash()
		}
		fmt.Fprintf(&advertisement, "%s\t%s\n", hash.String(), reference.Name().String())
	}
	return resolveAdvertisedReferences(advertisement.Bytes(), selector)
}

func newSSHSigner(t *testing.T) (gossh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, private
}

func startSSHAgent(t *testing.T, private ed25519.PrivateKey) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private, Comment: "differential-test"}); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]bool)
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connectionsMu.Lock()
			connections[connection] = true
			connectionsMu.Unlock()
			wait.Add(1)
			go func() {
				defer wait.Done()
				defer func() {
					connectionsMu.Lock()
					delete(connections, connection)
					connectionsMu.Unlock()
					_ = connection.Close()
				}()
				_ = agent.ServeAgent(keyring, connection)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		connectionsMu.Lock()
		for connection := range connections {
			_ = connection.Close()
		}
		connectionsMu.Unlock()
		wait.Wait()
	})
	return socket
}

func startGitSSHServer(t *testing.T, repository string, hostSigner gossh.Signer, allowedKey gossh.PublicKey) string {
	t.Helper()
	gitExecutable, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	server := &serverssh.Server{
		PublicKeyHandler: func(_ serverssh.Context, key serverssh.PublicKey) bool {
			return bytes.Equal(key.Marshal(), allowedKey.Marshal())
		},
		Handler: func(session serverssh.Session) {
			commandArguments := session.Command()
			if len(commandArguments) != 2 || commandArguments[0] != "git-upload-pack" || !strings.HasSuffix(commandArguments[1], "/remote.git") {
				_, _ = fmt.Fprintln(session.Stderr(), "unsupported Git SSH command")
				_ = session.Exit(1)
				return
			}
			command := exec.CommandContext(session.Context(), gitExecutable, "upload-pack", repository)
			command.Env = testgit.Environment()
			command.Stdin = session
			command.Stdout = session
			command.Stderr = session.Stderr()
			if err := command.Run(); err != nil {
				_ = session.Exit(1)
			}
		},
	}
	server.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
	})
	return listener.Addr().String()
}
