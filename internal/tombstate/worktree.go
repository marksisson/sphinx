package tombstate

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/marksisson/sphinx/internal/gitresource"
	"github.com/marksisson/sphinx/internal/managedpath"
)

var worktreeRotationPattern = regexp.MustCompile(`^\.tomb/rotations/([0-9]{8})(\.yaml|\.from\.sig|\.to\.sig)$`)

// LoadWorktreeContent reads the complete canonical managed state without consulting the index.
func LoadWorktreeContent(root string) (*gitresource.Content, error) {
	content := &gitresource.Content{Artifacts: map[string]gitresource.Blob{}, Schemas: map[string]gitresource.Blob{}, Rotations: map[int]gitresource.RotationBlobs{}}
	read := func(path string) (gitresource.Blob, error) {
		data, err := readRegular(root, path)
		return gitresource.Blob{Path: path, Data: data}, err
	}
	var err error
	if content.Manifest, err = read(".tomb/tomb.yaml"); err != nil {
		return nil, err
	}
	if content.Decree, err = read(".tomb/decree.yaml"); err != nil {
		return nil, err
	}
	if content.Signature, err = read(".tomb/decree.yaml.sig"); err != nil {
		return nil, err
	}
	keep, err := readRegular(root, ".tomb/rotations/.keep")
	if err != nil {
		return nil, err
	}
	if len(keep) != 0 {
		return nil, fmt.Errorf(".tomb/rotations/.keep must be empty")
	}
	entries, err := managedpath.Discover(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		blob, err := read(entry.Path)
		if err != nil {
			return nil, err
		}
		if entry.Kind == managedpath.Artifact {
			content.Artifacts[entry.Key] = blob
		} else {
			content.Schemas[entry.Key] = blob
		}
	}
	rotationPaths := []string{}
	err = filepath.WalkDir(filepath.Join(root, ".tomb"), func(filename string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		path := filepath.ToSlash(relative)
		if path == ".tomb/tomb.yaml" || path == ".tomb/decree.yaml" || path == ".tomb/decree.yaml.sig" || path == ".tomb/rotations/.keep" {
			return nil
		}
		if _, ok := managedpath.Classify(path); ok {
			return nil
		}
		if worktreeRotationPattern.MatchString(path) {
			rotationPaths = append(rotationPaths, path)
			return nil
		}
		return fmt.Errorf("unsupported or non-canonical tomb metadata path %q", path)
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(rotationPaths)
	masks := map[int]uint8{}
	for _, path := range rotationPaths {
		match := worktreeRotationPattern.FindStringSubmatch(path)
		sequence, _ := strconv.Atoi(match[1])
		if sequence == 0 {
			return nil, fmt.Errorf("rotation sequence must start at one")
		}
		blob, err := read(path)
		if err != nil {
			return nil, err
		}
		group := content.Rotations[sequence]
		switch match[2] {
		case ".yaml":
			group.Transition = blob
			masks[sequence] |= 1
		case ".from.sig":
			group.From = blob
			masks[sequence] |= 2
		case ".to.sig":
			group.To = blob
			masks[sequence] |= 4
		}
		content.Rotations[sequence] = group
	}
	for sequence := 1; sequence <= len(masks); sequence++ {
		if masks[sequence] != 7 {
			return nil, fmt.Errorf("rotation sequence %08d is missing, incomplete, or non-contiguous", sequence)
		}
	}
	if len(content.Schemas) == 0 {
		return nil, fmt.Errorf("tomb contains no canonical schemas")
	}
	return content, nil
}
func readRegular(root, path string) ([]byte, error) {
	filename := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("managed tomb path %q is not a regular non-symlink file", path)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if strings.ContainsRune(path, '\x00') {
		return nil, fmt.Errorf("managed tomb path is invalid")
	}
	return data, nil
}
