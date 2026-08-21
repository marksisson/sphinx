package tomb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

const ConfigurationPath = ".sphinx/tomb.yaml"

type Configuration struct {
	Format    int                   `yaml:"format"`
	PublicKey string                `yaml:"public_key"`
	Recovery  RecoveryConfiguration `yaml:"recovery"`
}

type RecoveryConfiguration struct {
	Type           string `yaml:"type"`
	EncryptedCheck string `yaml:"encrypted_check"`
}

func LoadConfiguration(root string) (*Configuration, error) {
	directory := filepath.Join(root, ".sphinx")
	if info, err := os.Lstat(directory); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("tomb configuration directory is a symlink")
	} else if err != nil {
		return nil, err
	}
	filename := filepath.Join(root, ConfigurationPath)
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("tomb configuration is a symlink")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var configuration Configuration
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&configuration); err != nil {
		return nil, fmt.Errorf("parse tomb configuration: %w", err)
	}
	if configuration.Format != 1 {
		return nil, fmt.Errorf("unsupported tomb configuration format %d", configuration.Format)
	}
	if configuration.PublicKey == "" || configuration.Recovery.Type == "" || configuration.Recovery.EncryptedCheck == "" {
		return nil, fmt.Errorf("tomb configuration is incomplete")
	}
	return &configuration, nil
}

func WriteConfiguration(root string, configuration Configuration) error {
	if configuration.Format != 1 {
		return fmt.Errorf("unsupported tomb configuration format %d", configuration.Format)
	}
	data, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	directory := filepath.Join(root, ".sphinx")
	if info, err := os.Lstat(directory); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("tomb configuration directory is a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".tomb.yaml.*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(root, ConfigurationPath))
}
