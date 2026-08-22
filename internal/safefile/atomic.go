// Package safefile centralizes crash-safe replacement of caller-managed files.
package safefile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WriteAtomic writes data to a private temporary file, fsyncs it, atomically
// replaces filename, and fsyncs the containing directory. Existing regular-file
// permissions are preserved. No content-size limit is imposed. Callers needing
// a repository containment boundary use WriteAtomicWithin.
func WriteAtomic(filename string, data []byte, createMode fs.FileMode) error {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("resolve destination: %w", err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return fmt.Errorf("resolve destination directory: %w", err)
	}
	return writeAtomic(filepath.Join(directory, filepath.Base(absolute)), data, createMode)
}

// WriteAtomicWithin rejects absolute/traversing relative paths and every
// symlink below root before performing an atomic write inside root.
func WriteAtomicWithin(root, relative string, data []byte, createMode fs.FileMode) error {
	if relative == "" || filepath.IsAbs(relative) {
		return fmt.Errorf("destination must be relative to the trusted root")
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("destination escapes the trusted root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve trusted root: %w", err)
	}
	current := resolvedRoot
	components := strings.Split(clean, string(filepath.Separator))
	for _, component := range components[:len(components)-1] {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect destination component %s: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination component %s must be a non-symlink directory", current)
		}
	}
	return writeAtomic(filepath.Join(resolvedRoot, clean), data, createMode)
}

func writeAtomic(absolute string, data []byte, createMode fs.FileMode) error {
	mode := createMode.Perm()
	if mode == 0 {
		return fmt.Errorf("destination mode must be nonzero")
	}
	if info, err := os.Lstat(absolute); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination must be a regular non-symlink file")
		}
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect destination: %w", err)
	} else if mode&0o111 != 0 {
		return fmt.Errorf("new destination mode must be non-executable")
	}

	directory := filepath.Dir(absolute)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect destination directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination parent must be a non-symlink directory")
	}

	temporary, err := os.CreateTemp(directory, ".sphinx-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary-file mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryName, absolute); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	keep = true

	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open destination directory for sync: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync destination directory: %w", err)
	}
	return nil
}
