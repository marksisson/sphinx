// Package runtime owns process-global go-git initialization and resources.
// It must be initialized before any repository is opened.
package runtime

import (
	"fmt"
	"reflect"
	"sync"

	gitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/x/fdpool"
	"github.com/go-git/go-git/v6/x/plugin"
	xconfig "github.com/go-git/go-git/v6/x/plugin/config"
)

const (
	// DependencyCommit is the reviewed go-git main commit used by Sphinx.
	DependencyCommit = "374c354884f12ea0a8f80ae9c429a44a33ba4bb1"
	// DependencyVersion is the exact reproducible module pseudo-version for DependencyCommit.
	DependencyVersion = "v6.0.0-alpha.5.0.20260821142625-374c354884f1"

	descriptorPoolCapacity = 256
)

var (
	initializeOnce sync.Once
	initializeErr  error
	descriptorPool *fdpool.Pool
)

// Initialize replaces go-git's ambient global/system configuration source
// with immutable empty configuration, freezes that choice, and creates the
// process-wide bounded descriptor pool. A failed first initialization remains
// failed for the life of the process.
func Initialize() error {
	initializeOnce.Do(func() {
		if err := plugin.Register(plugin.ConfigLoader(), func() plugin.ConfigSource {
			return xconfig.NewEmpty()
		}); err != nil {
			initializeErr = fmt.Errorf("register isolated go-git configuration: %w", err)
			return
		}

		source, err := plugin.Get(plugin.ConfigLoader())
		if err != nil {
			initializeErr = fmt.Errorf("freeze isolated go-git configuration: %w", err)
			return
		}
		for _, scope := range []gitconfig.Scope{gitconfig.GlobalScope, gitconfig.SystemScope} {
			storer, err := source.Load(scope)
			if err != nil {
				initializeErr = fmt.Errorf("load isolated go-git configuration scope %d: %w", scope, err)
				return
			}
			configuration, err := storer.Config()
			if err != nil {
				initializeErr = fmt.Errorf("read isolated go-git configuration scope %d: %w", scope, err)
				return
			}
			if !reflect.DeepEqual(configuration, gitconfig.NewConfig()) {
				initializeErr = fmt.Errorf("isolated go-git configuration scope %d is not empty", scope)
				return
			}
		}

		descriptorPool = fdpool.New(descriptorPoolCapacity)
	})
	return initializeErr
}

// DescriptorPool returns the shared bounded pool for filesystem-backed go-git
// storage. It initializes the process-global Git runtime if necessary.
func DescriptorPool() (*fdpool.Pool, error) {
	if err := Initialize(); err != nil {
		return nil, err
	}
	return descriptorPool, nil
}
