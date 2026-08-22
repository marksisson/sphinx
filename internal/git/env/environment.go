// Package env constructs a deterministic baseline for read-only Git
// subprocesses without inheriting repository/index/config redirection.
package env

import (
	"os"
	"strings"
)

var blocked = map[string]bool{
	"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_COMMON_DIR": true,
	"GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_NAMESPACE": true,
	"GIT_CONFIG_PARAMETERS": true, "GIT_CONFIG_COUNT": true,
	"GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_GLOBAL": true,
	"GIT_CONFIG_NOSYSTEM": true, "GIT_CEILING_DIRECTORIES": true,
}

func Environment() []string {
	environment := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !blocked[name] && !strings.HasPrefix(name, "GIT_CONFIG_KEY_") && !strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			environment = append(environment, entry)
		}
	}
	return append(environment, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
}
