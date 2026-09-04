package vault

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/raygj/ssf-relay/relay"
	"github.com/raygj/ssf-relay/sources"
)

func init() {
	sources.Register("vault-audit", func(cfg map[string]interface{}) (relay.Source, error) {
		return NewSource(cfg)
	})
}

// MountRule maps a path prefix to a secret engine and SSF event URI.
type MountRule struct {
	Prefix string `yaml:"prefix"`
	Engine string `yaml:"engine"`
	Event  string `yaml:"event"`
}

// Source parses Vault audit log JSON lines into relay.Events.
type Source struct {
	mountRules   []MountRule
	dropPrefixes []string
}

// NewSource constructs a vault audit Source from a config map.
func NewSource(cfg map[string]interface{}) (*Source, error) {
	s := &Source{}

	if v, ok := cfg["mount_rules"]; ok {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("vault source: marshal mount_rules: %w", err)
		}
		if err := json.Unmarshal(raw, &s.mountRules); err != nil {
			return nil, fmt.Errorf("vault source: parse mount_rules: %w", err)
		}
	}

	if v, ok := cfg["drop_prefixes"]; ok {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("vault source: marshal drop_prefixes: %w", err)
		}
		if err := json.Unmarshal(raw, &s.dropPrefixes); err != nil {
			return nil, fmt.Errorf("vault source: parse drop_prefixes: %w", err)
		}
	}

	return s, nil
}

func (s *Source) Name() string { return "vault-audit" }

// vaultAuditEntry is the subset of fields we care about from Vault audit JSON.
type vaultAuditEntry struct {
	Type string `json:"type"`
	Auth struct {
		TokenAccessor string `json:"token_accessor"`
		DisplayName   string `json:"display_name"`
		EntityID      string `json:"entity_id"`
	} `json:"auth"`
	Request struct {
		ID            string `json:"id"`
		Path          string `json:"path"`
		Operation     string `json:"operation"`
		EntityID      string `json:"entity_id"`
		RemoteAddress string `json:"remote_address"`
	} `json:"request"`
	Response struct {
		Secret struct {
			LeaseID       string `json:"lease_id"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"secret"`
	} `json:"response"`
	Error string `json:"error"`
}

// Parse implements relay.Source.
func (s *Source) Parse(line string) (relay.Event, bool) {
	var entry vaultAuditEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return relay.Event{}, false
	}

	// Only process response entries.
	if entry.Type != "response" {
		return relay.Event{}, false
	}

	path := entry.Request.Path
	op := entry.Request.Operation

	// Revoke check BEFORE drop prefixes (revokes go through sys/leases/revoke/...).
	isRevoke := op == "revoke" || strings.Contains(path, "/revoke")
	if isRevoke {
		return s.buildEvent(entry, "https://schemas.fiam/vault/credential-revoked", "", "")
	}

	// Apply drop prefixes.
	for _, prefix := range s.dropPrefixes {
		if strings.HasPrefix(path, prefix) {
			return relay.Event{}, false
		}
	}

	// Error → secret-denied.
	if entry.Error != "" {
		return s.buildEvent(entry, "https://schemas.fiam/vault/secret-denied", "", "")
	}

	// auth/*/login/* → auth-event.
	if strings.HasPrefix(path, "auth/") && strings.Contains(path, "/login") {
		return s.buildEvent(entry, "https://schemas.fiam/vault/auth-event", "", "")
	}

	// Match mount_rules.
	for _, rule := range s.mountRules {
		if strings.HasPrefix(path, rule.Prefix) {
			return s.buildEvent(entry, rule.Event, rule.Engine, rule.Prefix)
		}
	}

	// No match → drop.
	return relay.Event{}, false
}

func (s *Source) buildEvent(entry vaultAuditEntry, eventType, engine, _ string) (relay.Event, bool) {
	entityID := entry.Request.EntityID
	if entityID == "" {
		entityID = entry.Auth.EntityID
	}

	meta := map[string]string{
		"secret_path":      entry.Request.Path,
		"remote_address":   entry.Request.RemoteAddress,
		"vault_request_id": entry.Request.ID,
	}
	if engine != "" {
		meta["secret_engine"] = engine
	}
	if entry.Response.Secret.LeaseID != "" {
		meta["lease_id"] = entry.Response.Secret.LeaseID
		meta["ttl_seconds"] = fmt.Sprintf("%d", entry.Response.Secret.LeaseDuration)
	}
	if entry.Error != "" {
		meta["error"] = entry.Error
	}

	return relay.Event{
		Type:          eventType,
		CorrelationID: entry.Request.ID,
		Subject: relay.Subject{
			EntityID:   entityID,
			EntityName: entry.Auth.DisplayName,
			Accessor:   entry.Auth.TokenAccessor,
		},
		Metadata: meta,
	}, true
}
