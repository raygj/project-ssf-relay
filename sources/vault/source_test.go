package vault

import (
	"testing"
)

func newTestSource() *Source {
	s, _ := NewSource(map[string]interface{}{
		"mount_rules": []interface{}{
			map[string]interface{}{
				"prefix": "database/creds/",
				"engine": "database",
				"event":  "https://schemas.fiam/vault/credential-issued",
			},
			map[string]interface{}{
				"prefix": "kv/data/",
				"engine": "kv-v2",
				"event":  "https://schemas.fiam/vault/secret-accessed",
			},
		},
		"drop_prefixes": []interface{}{
			"sys/",
			"auth/token/lookup",
		},
	})
	return s
}

func TestParse_NonResponse(t *testing.T) {
	s := newTestSource()
	line := `{"type":"request","request":{"path":"database/creds/role","id":"req-1","operation":"read"}}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected non-response to be dropped")
	}
}

func TestParse_CredentialIssued(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-1","path":"database/creds/my-role","operation":"read","entity_id":"ent-1","remote_address":"1.2.3.4"},"auth":{"token_accessor":"acc-1","display_name":"user1","entity_id":"ent-1"},"response":{"secret":{"lease_id":"lease-1","lease_duration":3600}},"error":""}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/vault/credential-issued" {
		t.Errorf("unexpected event type: %s", ev.Type)
	}
	if ev.Metadata["secret_engine"] != "database" {
		t.Errorf("unexpected engine: %s", ev.Metadata["secret_engine"])
	}
	if ev.Metadata["lease_id"] != "lease-1" {
		t.Errorf("unexpected lease_id: %s", ev.Metadata["lease_id"])
	}
	if ev.Subject.EntityID != "ent-1" {
		t.Errorf("unexpected entity_id: %s", ev.Subject.EntityID)
	}
}

func TestParse_SecretAccessed(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-2","path":"kv/data/my-secret","operation":"read","entity_id":"ent-2","remote_address":"5.6.7.8"},"auth":{"token_accessor":"acc-2","display_name":"svc"},"response":{},"error":""}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/vault/secret-accessed" {
		t.Errorf("unexpected event type: %s", ev.Type)
	}
}

func TestParse_DropPrefix(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-3","path":"sys/health","operation":"read"},"auth":{},"response":{},"error":""}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected sys/ path to be dropped")
	}
}

func TestParse_SecretDenied(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-4","path":"kv/data/secret","operation":"read","entity_id":"ent-3","remote_address":"9.0.0.1"},"auth":{"token_accessor":"acc-3","display_name":"svc"},"response":{},"error":"permission denied"}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/vault/secret-denied" {
		t.Errorf("unexpected event type: %s", ev.Type)
	}
	if ev.Metadata["error"] != "permission denied" {
		t.Errorf("unexpected error: %s", ev.Metadata["error"])
	}
}

func TestParse_RevokeThroughSys(t *testing.T) {
	s := newTestSource()
	// sys/leases/revoke should be caught by revoke check before drop_prefixes
	line := `{"type":"response","request":{"id":"req-5","path":"sys/leases/revoke/database/creds/role/lease-1","operation":"update"},"auth":{},"response":{},"error":""}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected revoke event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/vault/credential-revoked" {
		t.Errorf("unexpected event type: %s", ev.Type)
	}
}

func TestParse_AuthLogin(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-6","path":"auth/userpass/login/alice","operation":"update"},"auth":{"display_name":"alice"},"response":{},"error":""}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected auth event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/vault/auth-event" {
		t.Errorf("unexpected event type: %s", ev.Type)
	}
}

func TestParse_NoMatch(t *testing.T) {
	s := newTestSource()
	line := `{"type":"response","request":{"id":"req-7","path":"cubbyhole/mydata","operation":"read"},"auth":{},"response":{},"error":""}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected unmatched path to be dropped")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := newTestSource()
	_, ok := s.Parse("not json")
	if ok {
		t.Error("expected invalid JSON to be dropped")
	}
}
