// Package seeker defines the live local identity consumed by decree policy. It
// intentionally contains no Tailscale client implementation.
package seeker

import (
	"fmt"
	"strings"
)

type Identity struct {
	Login    string
	Tags     []string
	NodeID   string
	NodeName string
}

func New(login string, tags []string) (Identity, error) {
	if login != strings.TrimSpace(login) {
		return Identity{}, fmt.Errorf("seeker login contains surrounding whitespace")
	}
	seen := make(map[string]bool, len(tags))
	copyTags := make([]string, len(tags))
	for index, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || len(tag) == len("tag:") || tag != strings.TrimSpace(tag) {
			return Identity{}, fmt.Errorf("seeker tag %q is invalid", tag)
		}
		if seen[tag] {
			return Identity{}, fmt.Errorf("seeker tag %q is duplicated", tag)
		}
		seen[tag] = true
		copyTags[index] = tag
	}
	if login == "" && len(copyTags) == 0 {
		return Identity{}, fmt.Errorf("seeker has neither a login nor a device tag")
	}
	return Identity{Login: login, Tags: copyTags}, nil
}
