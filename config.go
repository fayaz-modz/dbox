package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Runtime        string            `yaml:"runtime" json:"runtime"`
	RunPath        string            `yaml:"runpath" json:"runpath"`
	ContainersPath string            `yaml:"containers_path" json:"containers_path"`
	Registries     map[string]string `yaml:"registries,omitempty" json:"registries,omitempty"`
}

type ContainerConfig struct {
	Mounts []Mount `json:"mounts,omitempty"`
	SSH    *SSH    `json:"ssh,omitempty"`
	User   *User   `json:"user,omitempty"`
}

type Mount struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

type SSH struct {
	Enable bool `json:"enable"`
	Port   int  `json:"port,omitempty"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Wheel    bool   `json:"wheel"`
	Sudo     bool   `json:"sudo"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Try to create default config if not exists
		if os.IsNotExist(err) {
			return createDefaultConfig(path)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	ext := filepath.Ext(path)

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}

	// Validate and set defaults
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Runtime == "" {
		// Try to find runtime
		if path, err := findRuntime(); err == nil {
			c.Runtime = path
		} else {
			return fmt.Errorf("runtime not specified and could not be auto-detected")
		}
	}

	if c.RunPath == "" {
		c.RunPath = "/var/run/dbox"
	}

	if c.ContainersPath == "" {
		home, _ := os.UserHomeDir()
		c.ContainersPath = filepath.Join(home, ".local/share/dbox/containers")
	}

	// Create directories if they don't exist
	for _, dir := range []string{c.RunPath, c.ContainersPath} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Set default registries if not specified
	if c.Registries == nil {
		c.Registries = map[string]string{
			"alpine":    "docker.io/library/alpine",
			"ubuntu":    "docker.io/library/ubuntu",
			"archlinux": "docker.io/library/archlinux",
			"fedora":    "docker.io/library/fedora",
			"kali":      "docker.io/kalilinux/kali-rolling",
			"debian":    "docker.io/library/debian",
		}
	}

	return nil
}

func findRuntime() (string, error) {
	runtimes := []string{"crun", "runc"}

	for _, rt := range runtimes {
		if path, err := execLookPath(rt); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no supported runtime found (crun, runc)")
}

func execLookPath(name string) (string, error) {
	// Check common paths
	paths := []string{
		"/usr/bin/" + name,
		"/usr/local/bin/" + name,
		"/bin/" + name,
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("executable %s not found", name)
}

func createDefaultConfig(path string) (*Config, error) {
	cfg := &Config{
		RunPath:        "/var/run/dbox",
		ContainersPath: filepath.Join(os.Getenv("HOME"), ".local/share/dbox/containers"),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Try to save default config
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err == nil {
		data, _ := yaml.Marshal(cfg)
		os.WriteFile(path, data, 0644)
	}

	return cfg, nil
}

func LoadContainerConfig(path string) (*ContainerConfig, error) {
	if path == "" {
		return &ContainerConfig{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read container config: %w", err)
	}

	var cfg ContainerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse container config: %w", err)
	}

	return &cfg, nil
}
