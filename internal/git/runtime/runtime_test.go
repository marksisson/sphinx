package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/x/plugin"
)

func TestInitializeIsolatesAndFreezesConfiguration(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"global.gitconfig", "system.gitconfig"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("[user]\n\tname = hostile\n[remote \"origin\"]\n\turl = file:///untrusted\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(directory, "global.gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(directory, "system.gitconfig"))
	if err := Initialize(); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(); err != nil {
		t.Fatalf("second initialization: %v", err)
	}
	pool, err := DescriptorPool()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("descriptor pool is nil")
	}
	if stats := pool.Stats(); stats.Capacity != descriptorPoolCapacity {
		t.Fatalf("descriptor pool stats = %+v", stats)
	}

	source, err := plugin.Get(plugin.ConfigLoader())
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []gitconfig.Scope{gitconfig.GlobalScope, gitconfig.SystemScope} {
		storer, err := source.Load(scope)
		if err != nil {
			t.Fatal(err)
		}
		configuration, err := storer.Config()
		if err != nil {
			t.Fatal(err)
		}
		if configuration.User.Name != "" || len(configuration.Remotes) != 0 {
			t.Fatalf("scope %d inherited ambient configuration", scope)
		}
	}
	if err := plugin.Register(plugin.ConfigLoader(), func() plugin.ConfigSource { return source }); !errors.Is(err, plugin.ErrFrozen) {
		t.Fatalf("replace frozen configuration plugin: %v", err)
	}
}

func TestInitializeFailsIfConfigurationWasAlreadyResolved(t *testing.T) {
	if os.Getenv("SPHINX_TEST_FROZEN_GO_GIT_CONFIG") == "1" {
		if _, err := plugin.Get(plugin.ConfigLoader()); err != nil {
			t.Fatal(err)
		}
		if err := Initialize(); !errors.Is(err, plugin.ErrFrozen) {
			t.Fatalf("Initialize error = %v, want plugin.ErrFrozen", err)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestInitializeFailsIfConfigurationWasAlreadyResolved$")
	command.Env = append(os.Environ(), "SPHINX_TEST_FROZEN_GO_GIT_CONFIG=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
}

func TestPinnedDependencyVersion(t *testing.T) {
	goMod, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	pin := "github.com/go-git/go-git/v6 " + DependencyVersion
	if !strings.Contains(string(goMod), pin) {
		t.Fatalf("go.mod does not contain reviewed go-git pin %q", pin)
	}
	if !strings.HasSuffix(DependencyVersion, "-"+DependencyCommit[:12]) {
		t.Fatalf("go-git pseudo-version %q does not identify reviewed commit %s", DependencyVersion, DependencyCommit)
	}
}
