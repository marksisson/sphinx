package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marksisson/sphinx/internal/artifact"
	"github.com/marksisson/sphinx/internal/config"
	"github.com/marksisson/sphinx/internal/decree"
	gitresource "github.com/marksisson/sphinx/internal/git/resource"
	"github.com/marksisson/sphinx/internal/guardian"
	guardianstore "github.com/marksisson/sphinx/internal/guardian/store"
	hybridage "github.com/marksisson/sphinx/internal/hybrid/age"
	hybridsign "github.com/marksisson/sphinx/internal/hybrid/sign"
	"github.com/marksisson/sphinx/internal/proclamation"
	"github.com/marksisson/sphinx/internal/schema"
	"github.com/marksisson/sphinx/internal/seeker"
	testgit "github.com/marksisson/sphinx/internal/testgit"
	tombstate "github.com/marksisson/sphinx/internal/tomb/state"
	"github.com/spf13/cobra"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestFinalCommandTreeHasNoServiceOrRetiredCommands(t *testing.T) {
	a, _ := newApp(&bytes.Buffer{}, &bytes.Buffer{})
	root := newRootCommand(a)
	seen := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		seen[c.CommandPath()] = true
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	for _, required := range []string{"sphinx tomb add", "sphinx tomb update", "sphinx tomb status", "sphinx tomb list", "sphinx tomb remove", "sphinx tomb validate", "sphinx tomb recover", "sphinx artifact create", "sphinx artifact set-inscription", "sphinx artifact reseal", "sphinx artifact delete", "sphinx artifact inspect", "sphinx artifact reveal", "sphinx artifact validate", "sphinx guardian create", "sphinx guardian show", "sphinx guardian list", "sphinx guardian delete", "sphinx guardian add", "sphinx guardian remove", "sphinx decree init", "sphinx decree sign", "sphinx decree validate", "sphinx decree show", "sphinx proclamation rotate"} {
		if !seen[required] {
			t.Fatalf("missing %s", required)
		}
	}
	for path := range seen {
		lower := strings.ToLower(path)
		if strings.Contains(lower, "listen") || strings.Contains(lower, "online") {
			t.Fatalf("network command remains: %s", path)
		}
	}
	for _, command := range root.Commands() {
		walkFlags(t, command)
	}
}
func walkFlags(t *testing.T, command *cobra.Command) {
	t.Helper()
	for _, forbidden := range []string{"listen-address", "recovery", "stdin", "from-json", "clipboard", "output", "file", "fd", "exec"} {
		if command.Flags().Lookup(forbidden) != nil {
			t.Fatalf("forbidden flag --%s on %s", forbidden, command.CommandPath())
		}
	}
	for _, child := range command.Commands() {
		walkFlags(t, child)
	}
}

func TestJSONUsageEnvelopeAndSysexits(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--json", "artifact", "reveal", "--listen-address", "127.0.0.1:8080", "prod/api"}, &out, &errOut, nil)
	if code != 64 {
		t.Fatalf("exit=%d stderr=%s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("error stdout=%q", out.String())
	}
	var envelope struct {
		Version int  `json:"version"`
		OK      bool `json:"ok"`
		Error   struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Version != 1 || envelope.OK || envelope.Error.Code != "usage" {
		t.Fatalf("envelope=%+v", envelope)
	}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"--json", "tomb"}, &out, &errOut, nil)
	if code != 64 || out.Len() != 0 {
		t.Fatalf("group exit=%d stdout=%q", code, out.String())
	}
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil || envelope.Error.Code != "usage" {
		t.Fatalf("group envelope=%s err=%v", errOut.String(), err)
	}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"--json", "help", "artifact"}, &out, &errOut, nil)
	if code != 0 || errOut.Len() != 0 {
		t.Fatalf("help exit=%d stderr=%q", code, errOut.String())
	}
	var help map[string]any
	if err := json.Unmarshal(out.Bytes(), &help); err != nil || help["ok"] != true {
		t.Fatalf("help envelope=%q err=%v", out.String(), err)
	}
}

func TestSecurityControlPrecedesGuardianEnvironmentCapture(t *testing.T) {
	a, err := newApp(io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	a.disableCoreDumps = func() error { order = append(order, "core"); return nil }
	a.newGuardianStore = func() guardianOperations { order = append(order, "guardian"); return &cliGuardians{} }
	var out, errOut bytes.Buffer
	if code := runCLI([]string{"completion", "bash"}, &out, &errOut, a); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errOut.String())
	}
	if strings.Join(order, ",") != "core,guardian" {
		t.Fatalf("initialization order = %v", order)
	}
}

func TestSecurityControlFailureIsFailClosed(t *testing.T) {
	a, err := newApp(io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a.disableCoreDumps = func() error { return errors.New("denied") }
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--json", "completion", "bash"}, &out, &errOut, a)
	if code != 70 || out.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil || envelope.Error.Code != "security_control_failed" {
		t.Fatalf("envelope=%q err=%v", errOut.String(), err)
	}
}

type cliStatusClient struct {
	status *ipnstate.Status
	err    error
	calls  int
}

func (f *cliStatusClient) StatusWithoutPeers(context.Context) (*ipnstate.Status, error) {
	f.calls++
	return f.status, f.err
}

type cliGuardians struct{ record []byte }
type cliTerminal struct {
	answers [][]byte
	writes  bytes.Buffer
}

func (t *cliTerminal) Write(value []byte) (int, error) { return t.writes.Write(value) }
func (t *cliTerminal) ReadPassword(prompt []byte) ([]byte, error) {
	t.writes.Write(prompt)
	if len(t.answers) == 0 {
		return nil, errors.New("no answer")
	}
	value := append([]byte(nil), t.answers[0]...)
	t.answers = t.answers[1:]
	return value, nil
}
func (*cliTerminal) Close() error { return nil }

func (f *cliGuardians) Create(guardian.Name, guardian.Provider) (*guardian.Record, error) {
	return nil, guardianstore.ErrUnsupported
}
func (f *cliGuardians) Get(guardian.Name, guardian.Provider) (*guardian.Record, error) {
	return guardian.ParseRecord(f.record)
}
func (f *cliGuardians) List(guardian.Provider) ([]*guardian.Record, error) {
	return nil, guardianstore.ErrUnsupported
}
func (f *cliGuardians) Delete(guardian.Name, guardian.Provider) error {
	return guardianstore.ErrUnsupported
}

func TestInteractiveAuthoringRejectsMissingTerminalAndUnsupportedInput(t *testing.T) {
	fixture := newCLIFixture(t)
	defer fixture.signing.Destroy()
	fixture.app.openTerminal = func() (commandTerminal, error) { return nil, errors.New("no controlling terminal") }
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--json", "artifact", "create", "--tomb", "path:" + filepath.Dir(fixture.app.materializer.CacheRoot) + "/tomb", "--schema", "credential/v1", "new/item"}, &out, &errOut, fixture.app)
	if code != 74 || out.Len() != 0 {
		t.Fatalf("missing terminal exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"--json", "artifact", "create", "--stdin", "--tomb", "path:/invalid", "--schema", "credential/v1", "new/item"}, &out, &errOut, fixture.app)
	if code != 64 || out.Len() != 0 {
		t.Fatalf("unsupported input exit=%d stdout=%q", code, out.String())
	}
}

func TestTerminalRevealRequiresConfirmationBeforeSecretOutput(t *testing.T) {
	fixture := newCLIFixture(t)
	defer fixture.signing.Destroy()
	id := tailcfg.UserID(9)
	status := &ipnstate.Status{BackendState: "Running", HaveNodeKey: true, CurrentTailnet: &ipnstate.TailnetStatus{Name: "test"}, Self: &ipnstate.PeerStatus{UserID: id, Online: true}, User: map[tailcfg.UserID]tailcfg.UserProfile{id: {ID: id, LoginName: "alice@example.com"}}}
	fixture.app.seekers = seeker.TailscaleResolver{Client: &cliStatusClient{status: status}}
	fixture.app.outputIsTerminal = func(io.Writer) bool { return true }
	terminal := &cliTerminal{answers: [][]byte{[]byte("no")}}
	fixture.app.openTerminal = func() (commandTerminal, error) { return terminal, nil }
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--json", "artifact", "reveal", "--tomb", "default", "--secret", "token", "production/api"}, &out, &errOut, fixture.app)
	if code != 77 || out.Len() != 0 {
		t.Fatalf("JSON decline exit=%d stdout=%q", code, out.String())
	}
	var failure map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &failure); err != nil {
		t.Fatalf("JSON decline stderr=%q: %v", errOut.String(), err)
	}
	terminal.answers = [][]byte{[]byte("no")}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"artifact", "reveal", "--tomb", "default", "--secret", "token", "production/api"}, &out, &errOut, fixture.app)
	if code != 77 || out.Len() != 0 {
		t.Fatalf("decline exit=%d stdout=%q", code, out.String())
	}
	if strings.Contains(errOut.String(), "cli-secret") {
		t.Fatal("declined secret leaked")
	}
	terminal.answers = [][]byte{[]byte("yes")}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"artifact", "reveal", "--tomb", "default", "--secret", "token", "production/api"}, &out, &errOut, fixture.app)
	if code != 0 || out.String() != "cli-secret" {
		t.Fatalf("approved exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(errOut.String(), "cli-secret") {
		t.Fatal("secret leaked to diagnostics")
	}
}

func TestBlackBoxRevealUsesFreshFakeLocalAPIAndStdoutOnly(t *testing.T) {
	fixture := newCLIFixture(t)
	defer fixture.signing.Destroy()
	id := tailcfg.UserID(9)
	status := &ipnstate.Status{BackendState: "Running", HaveNodeKey: true, CurrentTailnet: &ipnstate.TailnetStatus{Name: "test"}, Self: &ipnstate.PeerStatus{UserID: id, Online: true}, User: map[tailcfg.UserID]tailcfg.UserProfile{id: {ID: id, LoginName: "alice@example.com"}}}
	client := &cliStatusClient{status: status}
	a := fixture.app
	a.seekers = seeker.TailscaleResolver{Client: client}
	var out, errOut bytes.Buffer
	code := runCLI([]string{"--json", "artifact", "reveal", "--tomb", "default", "--secret", "token", "production/api"}, &out, &errOut, a)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("secret reveal stderr=%q", errOut.String())
	}
	if client.calls != 1 {
		t.Fatalf("LocalAPI calls=%d", client.calls)
	}
	var envelope struct {
		Version int  `json:"version"`
		OK      bool `json:"ok"`
		Data    struct {
			Secrets map[string]any `json:"secrets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK || envelope.Data.Secrets["token"] != "cli-secret" {
		t.Fatalf("output=%s", out.String())
	}
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"--json", "artifact", "validate", "--tomb", "default", "production/api"}, &out, &errOut, a)
	if code != 0 || strings.Contains(out.String(), "cli-secret") || client.calls != 2 {
		t.Fatalf("validate exit=%d output=%q calls=%d", code, out.String(), client.calls)
	}
	client.status = nil
	out.Reset()
	errOut.Reset()
	code = runCLI([]string{"--json", "artifact", "reveal", "--tomb", "default", "production/api"}, &out, &errOut, a)
	if code != 69 || out.Len() != 0 {
		t.Fatalf("unavailable exit=%d stdout=%q", code, out.String())
	}
	var failed map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &failed); err != nil {
		t.Fatal(err)
	}
	body := failed["error"].(map[string]any)
	if body["code"] != "tailscale_unavailable" {
		t.Fatalf("error=%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "cli-secret") {
		t.Fatal("secret leaked to error")
	}
}

type cliFixture struct {
	app     *app
	signing *hybridsign.PrivateBundle
}

func newCLIFixture(t *testing.T) cliFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tomb := filepath.Join(root, "tomb")
	project := filepath.Join(root, "project")
	os.Mkdir(tomb, 0o700)
	os.Mkdir(project, 0o700)
	git(t, tomb, "init")
	git(t, project, "init")
	for _, dir := range []string{tomb, project} {
		git(t, dir, "config", "user.email", "test@example.invalid")
		git(t, dir, "config", "user.name", "Test")
	}
	proclamationIdentity, err := hybridage.IdentityFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signing, err := hybridsign.NewPrivate(bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	public := signing.Public()
	ed, ml := public.Encoded()
	fingerprint, _ := public.Fingerprint()
	salt := proclamation.Salt{}
	manifest := tombstate.Manifest{Version: 1, TombID: "123e4567-e89b-42d3-a456-426614174000", Proclamation: tombstate.Proclamation{KDF: proclamation.KDFSuite, Salt: salt.String(), AgeSuite: hybridage.Suite, AgeRecipient: hybridage.Recipient(proclamationIdentity), SignatureSuite: hybridsign.Suite, PublicKey: tombstate.PublicKey{Ed25519: ed, MLDSA65: ml}, Fingerprint: fingerprint}}
	manifestBytes, _ := tombstate.EncodeManifest(manifest)
	name, _ := guardian.ParseName("local")
	record, err := guardian.GenerateRecord(name, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, _ := record.MarshalJSON()
	definition := schema.Definition{Version: 1, Name: "credential", Secrets: []schema.Field{{Name: "token", Type: "string", Required: true, Prompt: "Token"}}}
	schemaBytes := []byte("version: 1\nname: credential\nsecrets:\n  - name: token\n    type: string\n    required: true\n    prompt: Token\n")
	engine := artifact.Engine{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 8192)), Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	encrypted, err := engine.Create(artifact.Document{Format: 1, Schema: "credential/v1", Inscriptions: map[string]any{}, Secrets: map[string]any{"token": "cli-secret"}}, definition, manifest.Proclamation.AgeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err = engine.AddRecipient(encrypted, proclamationIdentity, definition, record.Recipient())
	record.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string]gitresource.Blob{"production/api": {Path: "production/api/artifact.yaml", Data: encrypted}}
	schemas := map[string]gitresource.Blob{"credential/v1": {Path: ".tomb/schemas/credential/v1.yaml", Data: schemaBytes}}
	artifactLocks, schemaLocks := tombstate.Locks(artifacts, schemas)
	policy := decree.Document{Version: 1, Generation: 1, ArtifactLocks: artifactLocks, SchemaLocks: schemaLocks, Rules: []decree.Rule{{Name: "allow", Seekers: decree.Selectors{Logins: []string{"alice@example.com"}, Tags: []string{}}, Artifacts: []string{"production/**"}}}}
	decreeBytes, _ := decree.Encode(policy)
	signatureBytes, _ := tombstate.EncodeDecreeSignature(manifestBytes, decreeBytes, manifest, signing)
	files := map[string][]byte{".tomb/tomb.yaml": manifestBytes, ".tomb/decree.yaml": decreeBytes, ".tomb/decree.yaml.sig": signatureBytes, ".tomb/rotations/.keep": {}, ".tomb/schemas/credential/v1.yaml": schemaBytes, "production/api/artifact.yaml": encrypted}
	for path, data := range files {
		filename := filepath.Join(tomb, filepath.FromSlash(path))
		os.MkdirAll(filepath.Dir(filename), 0o700)
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git(t, tomb, "add", ".")
	git(t, tomb, "commit", "-m", "initial")
	commit := gitOutput(t, tomb, "rev-parse", "HEAD")
	reference := "path:" + tomb
	projectConfig := config.Project{Version: 1, Tombs: map[string]config.ProjectTomb{"default": {Reference: reference, Lock: config.Lock{Commit: commit, ProclamationFingerprint: fingerprint, DecreeGeneration: 1, LockedAt: time.Now().UTC()}, Guardians: []config.GuardianSelection{{Name: name, Provider: guardian.Environment}}}}}
	encoded, err := config.EncodeProject(projectConfig)
	if err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(project, ".sphinx"), 0o700)
	if err := os.WriteFile(filepath.Join(project, ".sphinx/config.yaml"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, project, "add", ".")
	git(t, project, "commit", "-m", "project")
	a, err := newApp(&bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	a.cwd = func() (string, error) { return project, nil }
	a.materializer = gitresource.Materializer{CacheRoot: filepath.Join(root, "cache")}
	a.guardians = &cliGuardians{record: recordBytes}
	return cliFixture{app: a, signing: signing}
}
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = testgit.Environment()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s", args, out)
	}
}
func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = testgit.Environment()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
