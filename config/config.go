package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level ssf-relay configuration.
type Config struct {
	SSF     SSFConfig      `yaml:"ssf"`
	Sources []SourceConfig `yaml:"sources"`
	Sinks   []SinkConfig   `yaml:"sinks"`
}

// SSFConfig holds SSF transmitter settings.
type SSFConfig struct {
	ReceiverURL       string `yaml:"receiver_url"`
	Issuer            string `yaml:"issuer"`
	TimeoutSecs       int    `yaml:"timeout_secs"`
	SigningKeyPEMFile string `yaml:"signing_key_pem_file"` // path to EC PRIVATE KEY PEM file
	SigningKeyPEM     string `yaml:"signing_key_pem"`      // inline PEM (takes precedence over file)
	JWKSAddr          string `yaml:"jwks_addr"`            // optional: serve GET /jwks on this addr (e.g. ":9100")
}

// ResolveSigningKeyPEM returns the PEM bytes for the signing key, preferring
// the inline value over the file path. Returns nil, nil when signing is not configured.
func (c *SSFConfig) ResolveSigningKeyPEM() ([]byte, error) {
	if c.SigningKeyPEM != "" {
		return []byte(c.SigningKeyPEM), nil
	}
	if c.SigningKeyPEMFile != "" {
		data, err := os.ReadFile(c.SigningKeyPEMFile)
		if err != nil {
			return nil, fmt.Errorf("read signing key file %q: %w", c.SigningKeyPEMFile, err)
		}
		return data, nil
	}
	return nil, nil
}

// SinkConfig describes a single inbound signal handler.
type SinkConfig struct {
	EventType string                 `yaml:"event_type"`
	Action    string                 `yaml:"action"`
	Config    map[string]interface{} `yaml:"config"`
}

// SourceConfig describes a single log source.
type SourceConfig struct {
	Name      string                 `yaml:"name"`
	Type      string                 `yaml:"type"`
	Transport string                 `yaml:"transport"` // "file" (default) | "socket"
	Path      string                 `yaml:"path"`      // file path or socket address
	Config    map[string]interface{} `yaml:"config"`
}

// Load reads and parses a YAML config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.SSF.TimeoutSecs <= 0 {
		cfg.SSF.TimeoutSecs = 5
	}
	return cfg, nil
}
