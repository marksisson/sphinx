// Package path discovers canonical artifact and schema paths in a
// caller-managed tomb worktree without following symlinks.
package path

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/marksisson/sphinx/internal/chamber"
)

type Kind uint8

const (
	Artifact Kind = iota + 1
	Schema
)

type Entry struct {
	Path string
	Key  string
	Kind Kind
}

var schemaPattern = regexp.MustCompile(`^\.tomb/schemas/([a-z][a-z0-9-]*)/(v[1-9][0-9]*)\.yaml$`)

func Classify(path string) (Entry, bool) {
	if matches := schemaPattern.FindStringSubmatch(path); matches != nil {
		return Entry{Path: path, Key: matches[1] + "/" + matches[2], Kind: Schema}, true
	}
	if strings.HasSuffix(path, "/"+chamber.ArtifactFilename) && !strings.HasPrefix(path, ".tomb/") {
		value := strings.TrimSuffix(path, "/"+chamber.ArtifactFilename)
		parsed, err := chamber.Parse(value)
		if err == nil && parsed.ArtifactPath() == path {
			return Entry{Path: path, Key: value, Kind: Artifact}, true
		}
	}
	return Entry{}, false
}

func Discover(root string) ([]Entry, error) {
	entries := []Entry{}
	err := filepath.WalkDir(root, func(filename string, item fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		path := filepath.ToSlash(relative)
		if item.IsDir() {
			if path == ".git" || strings.HasPrefix(path, ".git/") {
				return filepath.SkipDir
			}
			return nil
		}
		entry, managed := Classify(path)
		if !managed {
			return nil
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("managed tomb path %q is not a regular non-symlink file", path)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
