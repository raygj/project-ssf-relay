package opa

import (
	"encoding/json"
	"fmt"

	"github.com/raygj/ssf-relay/relay"
	"github.com/raygj/ssf-relay/sources"
)

func init() {
	sources.Register("opa-decision", func(cfg map[string]interface{}) (relay.Source, error) {
		return NewSource(cfg)
	})
}

// Source parses OPA decision log JSON lines into relay.Events.
type Source struct {
	emitAllow bool
	dropPaths map[string]bool
}

// NewSource constructs an OPA decision Source from a config map.
func NewSource(cfg map[string]interface{}) (*Source, error) {
	s := &Source{
		dropPaths: map[string]bool{},
	}

	if v, ok := cfg["emit_allow"]; ok {
		switch val := v.(type) {
		case bool:
			s.emitAllow = val
		default:
			return nil, fmt.Errorf("opa source: emit_allow must be bool")
		}
	}

	if v, ok := cfg["drop_paths"]; ok {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("opa source: marshal drop_paths: %w", err)
		}
		var paths []string
		if err := json.Unmarshal(raw, &paths); err != nil {
			return nil, fmt.Errorf("opa source: parse drop_paths: %w", err)
		}
		for _, p := range paths {
			s.dropPaths[p] = true
		}
	}

	return s, nil
}

func (s *Source) Name() string { return "opa-decision" }

// opaDecision is the subset of fields we care about from OPA decision logs.
type opaDecision struct {
	DecisionID string                 `json:"decision_id"`
	Path       string                 `json:"path"`
	Result     interface{}            `json:"result"`
	Labels     map[string]string      `json:"labels"`
	Input      map[string]interface{} `json:"input"`
}

// Parse implements relay.Source.
func (s *Source) Parse(line string) (relay.Event, bool) {
	var entry opaDecision
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return relay.Event{}, false
	}

	// Apply drop_paths filter.
	if s.dropPaths[entry.Path] {
		return relay.Event{}, false
	}

	// Determine result: OPA result can be bool or complex object.
	// For classification we treat non-false as allowed.
	allowed := isAllowed(entry.Result)

	var eventType string
	if !allowed {
		eventType = "https://schemas.fiam/relay/opa/policy-denied"
	} else if s.emitAllow {
		eventType = "https://schemas.fiam/relay/opa/policy-allowed"
	} else {
		// Drop allowed decisions when emit_allow=false.
		return relay.Event{}, false
	}

	instanceID := entry.Labels["id"]
	version := entry.Labels["version"]

	return relay.Event{
		Type:          eventType,
		CorrelationID: entry.DecisionID,
		Subject: relay.Subject{
			EntityName: instanceID,
		},
		Metadata: map[string]string{
			"opa_path":        entry.Path,
			"opa_decision_id": entry.DecisionID,
			"opa_instance":    instanceID,
			"opa_version":     version,
		},
	}, true
}

// isAllowed returns false only when result is the boolean false.
func isAllowed(result interface{}) bool {
	if b, ok := result.(bool); ok {
		return b
	}
	// Non-boolean results (objects, arrays) count as allowed / truthy.
	return result != nil
}
