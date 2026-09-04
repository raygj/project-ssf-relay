package opa

import (
	"testing"
)

func newTestSource(emitAllow bool) *Source {
	s, _ := NewSource(map[string]interface{}{
		"emit_allow": emitAllow,
		"drop_paths": []interface{}{
			"data.system.main",
		},
	})
	return s
}

const deniedLine = `{"decision_id":"dec-1","path":"data.policy.allow","result":false,"labels":{"id":"opa-prod","version":"0.63.0"}}`
const allowedLine = `{"decision_id":"dec-2","path":"data.policy.allow","result":true,"labels":{"id":"opa-prod","version":"0.63.0"}}`
const dropLine = `{"decision_id":"dec-3","path":"data.system.main","result":true,"labels":{"id":"opa-prod","version":"0.63.0"}}`

func TestParse_PolicyDenied(t *testing.T) {
	s := newTestSource(false)
	ev, ok := s.Parse(deniedLine)
	if !ok {
		t.Fatal("expected denied event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/opa/policy-denied" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
	if ev.CorrelationID != "dec-1" {
		t.Errorf("unexpected correlation_id: %s", ev.CorrelationID)
	}
	if ev.Subject.EntityName != "opa-prod" {
		t.Errorf("unexpected entity_name: %s", ev.Subject.EntityName)
	}
	if ev.Metadata["opa_version"] != "0.63.0" {
		t.Errorf("unexpected opa_version: %s", ev.Metadata["opa_version"])
	}
}

func TestParse_AllowedDropped_EmitAllowFalse(t *testing.T) {
	s := newTestSource(false)
	_, ok := s.Parse(allowedLine)
	if ok {
		t.Error("expected allowed decision to be dropped when emit_allow=false")
	}
}

func TestParse_AllowedEmitted_EmitAllowTrue(t *testing.T) {
	s := newTestSource(true)
	ev, ok := s.Parse(allowedLine)
	if !ok {
		t.Fatal("expected allowed event to be emitted when emit_allow=true")
	}
	if ev.Type != "https://schemas.fiam/relay/opa/policy-allowed" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
}

func TestParse_DropPath(t *testing.T) {
	s := newTestSource(true)
	_, ok := s.Parse(dropLine)
	if ok {
		t.Error("expected data.system.main to be dropped")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := newTestSource(false)
	_, ok := s.Parse("not json")
	if ok {
		t.Error("expected invalid JSON to be dropped")
	}
}

func TestParse_NonBoolResultAllowed(t *testing.T) {
	s := newTestSource(true)
	line := `{"decision_id":"dec-4","path":"data.policy.rules","result":{"allow":true},"labels":{"id":"opa-prod","version":"0.63.0"}}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected non-bool result to be treated as allowed and emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/opa/policy-allowed" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
}

func TestParse_NullResult(t *testing.T) {
	s := newTestSource(true)
	// null result → isAllowed returns false → policy-denied
	line := `{"decision_id":"dec-5","path":"data.policy.allow","result":null,"labels":{"id":"opa-prod","version":"0.63.0"}}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected null result to emit (as denied)")
	}
	if ev.Type != "https://schemas.fiam/relay/opa/policy-denied" {
		t.Errorf("unexpected type for null result: %s", ev.Type)
	}
}
