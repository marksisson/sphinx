package differential

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v6"
	gogitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/client"
	"github.com/go-git/go-git/v6/storage/memory"
	testgit "github.com/marksisson/sphinx/internal/testgit"
)

func TestSmartHTTPSAdvertisementAndMirrorCloneMatchNativeGit(t *testing.T) {
	fixture := createRepository(t, "sha1")
	projectRoot := t.TempDir()
	bare := filepath.Join(projectRoot, "remote.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, bare)
	server := newQuietTLSServer(gitHTTPBackend(projectRoot))
	defer server.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteURL := server.URL + "/remote.git"

	if _, err := nativeHTTPSList(context.Background(), remoteURL, "", ""); err == nil {
		t.Fatal("native Git trusted the test HTTPS server without its CA")
	}
	if _, err := goGitHTTPSList(context.Background(), remoteURL, "", nil); err == nil {
		t.Fatal("go-git trusted the test HTTPS server without its CA")
	}

	for _, selector := range []string{"", "lightweight", "annotated"} {
		want, err := nativeHTTPSList(context.Background(), remoteURL, selector, caFile)
		if err != nil {
			t.Fatalf("native HTTPS selector %q: %v", selector, err)
		}
		got, err := goGitHTTPSList(context.Background(), remoteURL, selector, caPEM)
		if err != nil {
			t.Fatalf("go-git HTTPS selector %q: %v", selector, err)
		}
		if got != want {
			t.Fatalf("HTTPS selector %q disagreement: native=%s go-git=%s", selector, want, got)
		}
	}

	nativeClone := filepath.Join(t.TempDir(), "native.git")
	candidateClone := filepath.Join(t.TempDir(), "candidate.git")
	if err := nativeHTTPSClone(context.Background(), remoteURL, nativeClone, caFile); err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainCloneContext(context.Background(), candidateClone, &git.CloneOptions{
		URL: remoteURL, Mirror: true, Bare: true, Tags: git.AllTags,
		ClientOptions: []client.Option{client.WithCABundle(caPEM)},
	})
	if repository != nil {
		closeRepository(repository)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, clone := range []string{nativeClone, candidateClone} {
		if err := (goGitAdapter{}).CommitExists(context.Background(), clone, fixture.secondCommit); err != nil {
			t.Fatalf("mirror clone %q lacks approved commit: %v", clone, err)
		}
	}
}

func TestMalformedSmartHTTPSAdvertisementFailsClosed(t *testing.T) {
	server := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = writer.Write([]byte("this-is-not-a-valid-pkt-line"))
	}))
	defer server.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteURL := server.URL + "/remote.git"
	if _, err := nativeHTTPSList(context.Background(), remoteURL, "", caFile); err == nil {
		t.Fatal("native Git accepted malformed HTTPS advertisement")
	}
	if _, err := goGitHTTPSList(context.Background(), remoteURL, "", caPEM); err == nil {
		t.Fatal("go-git accepted malformed HTTPS advertisement")
	}
}

func TestSmartHTTPSCancellation(t *testing.T) {
	fixture := createRepository(t, "sha1")
	projectRoot := t.TempDir()
	bare := filepath.Join(projectRoot, "remote.git")
	runGit(t, fixture.root, "clone", "-q", "--bare", fixture.root, bare)
	backend := gitHTTPBackend(projectRoot)
	server := newQuietTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(2 * time.Second):
			backend.ServeHTTP(writer, request)
		}
	}))
	defer server.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	remoteURL := server.URL + "/remote.git"

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := goGitHTTPSList(ctx, remoteURL, "", caPEM); err == nil {
		t.Fatal("cancelled go-git advertisement succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("go-git cancellation took %s", elapsed)
	}
}

func nativeHTTPSList(ctx context.Context, remoteURL, selector, caFile string) (string, error) {
	patterns := []string{"HEAD"}
	if selector != "" {
		patterns = []string{"refs/heads/" + selector, "refs/tags/" + selector, "refs/tags/" + selector + "^{}"}
	}
	arguments := append([]string{"ls-remote", "--", remoteURL}, patterns...)
	command := exec.CommandContext(ctx, "git", arguments...)
	command.Env = testgit.Environment()
	if caFile != "" {
		command.Env = append(command.Env, "GIT_SSL_CAINFO="+caFile)
	} else {
		command.Env = append(command.Env, "GIT_SSL_CAINFO=/dev/null")
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("native HTTPS advertisement: %w", err)
	}
	return resolveAdvertisedReferences(output, selector)
}

func goGitHTTPSList(ctx context.Context, remoteURL, selector string, caPEM []byte) (string, error) {
	remote := git.NewRemote(memory.NewStorage(), &gogitconfig.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	options := &git.ListOptions{PeelingOption: git.AppendPeeled}
	if caPEM != nil {
		options.ClientOptions = []client.Option{client.WithCABundle(caPEM)}
	}
	references, err := remote.ListContext(ctx, options)
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

func nativeHTTPSClone(ctx context.Context, remoteURL, destination, caFile string) error {
	command := exec.CommandContext(ctx, "git", "clone", "--mirror", "--no-hardlinks", "--", remoteURL, destination)
	command.Env = append(testgit.Environment(), "GIT_SSL_CAINFO="+caFile)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("native HTTPS clone: %w: %s", err, output)
	}
	return nil
}

func newQuietTLSServer(handler http.Handler) *httptest.Server {
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	return server
}

func gitHTTPBackend(projectRoot string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		command := exec.CommandContext(request.Context(), "git", "http-backend")
		command.Env = append(testgit.Environment(),
			"GIT_PROJECT_ROOT="+projectRoot,
			"GIT_HTTP_EXPORT_ALL=1",
			"PATH_INFO="+request.URL.Path,
			"QUERY_STRING="+request.URL.RawQuery,
			"REQUEST_METHOD="+request.Method,
			"CONTENT_TYPE="+request.Header.Get("Content-Type"),
			"CONTENT_LENGTH="+strconv.FormatInt(request.ContentLength, 10),
			"SERVER_PROTOCOL="+request.Proto,
			"REMOTE_ADDR="+request.RemoteAddr,
		)
		command.Stdin = request.Body
		output, err := command.Output()
		if err != nil {
			http.Error(writer, "Git backend unavailable", http.StatusBadGateway)
			return
		}
		reader := bufio.NewReader(bytes.NewReader(output))
		headers, err := textproto.NewReader(reader).ReadMIMEHeader()
		if err != nil {
			http.Error(writer, "Malformed Git backend response", http.StatusBadGateway)
			return
		}
		status := http.StatusOK
		if value := headers.Get("Status"); value != "" {
			fields := strings.Fields(value)
			if len(fields) != 0 {
				if parsed, parseErr := strconv.Atoi(fields[0]); parseErr == nil {
					status = parsed
				}
			}
			headers.Del("Status")
		}
		for name, values := range headers {
			for _, value := range values {
				writer.Header().Add(name, value)
			}
		}
		writer.WriteHeader(status)
		_, _ = io.Copy(writer, reader)
	})
}
