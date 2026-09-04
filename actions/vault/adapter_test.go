package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/raygj/ssf-relay/relay"
)

func TestAdapter_RevokeSelf(t *testing.T) {
	var revokeCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/auth/token/revoke-self"):
			if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
				t.Errorf("X-Vault-Token: want test-token got %q", got)
			}
			revokeCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "test-token")

	a, err := NewAdapter(map[string]interface{}{
		"vault_addr":      srv.URL,
		"vault_token_env": "VAULT_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}

	set := relay.InboundSET{
		EventType: eventCompromised,
		SourceID:  "demo-workload",
	}
	if err := a.Act(context.Background(), set); err != nil {
		t.Fatalf("Act: %v", err)
	}
	if !revokeCalled {
		t.Fatal("expected revoke-self to be called")
	}
}

func TestAdapter_RevokeSelf_AlreadyRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "dead-token")

	a, err := NewAdapter(map[string]interface{}{"vault_addr": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Act(context.Background(), relay.InboundSET{EventType: eventCompromised}); err != nil {
		t.Fatalf("403 revoke-self should be treated as success: %v", err)
	}
}

func TestAdapter_FlagEntityDegraded(t *testing.T) {
	const entityID = "ent-abc"
	var gotMetadata map[string]string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/auth/token/lookup-self"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]string{"entity_id": entityID},
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/identity/entity/id/"+entityID):
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Metadata map[string]string `json:"metadata"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode entity update: %v", err)
			}
			gotMetadata = req.Metadata
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("VAULT_TOKEN", "test-token")

	a, err := NewAdapter(map[string]interface{}{"vault_addr": srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	set := relay.InboundSET{
		EventType:     eventDegraded,
		SourceID:      "src-1",
		CorrelationID: "corr-1",
	}
	if err := a.Act(context.Background(), set); err != nil {
		t.Fatalf("Act degraded: %v", err)
	}
	if gotMetadata["ssf_status"] != "degraded" {
		t.Errorf("ssf_status: want degraded got %q", gotMetadata["ssf_status"])
	}
	if gotMetadata["ssf_source_id"] != "src-1" {
		t.Errorf("ssf_source_id: want src-1 got %q", gotMetadata["ssf_source_id"])
	}
}

func TestAdapter_RevokeSelf_MissingToken(t *testing.T) {
	a, err := NewAdapter(map[string]interface{}{"vault_addr": "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("VAULT_TOKEN")
	if err := a.Act(context.Background(), relay.InboundSET{EventType: eventCompromised}); err == nil {
		t.Fatal("expected error when VAULT_TOKEN is empty")
	}
}

func TestAdapter_EventTypes(t *testing.T) {
	a, err := NewAdapter(nil)
	if err != nil {
		t.Fatal(err)
	}
	types := a.EventTypes()
	if len(types) != 3 {
		t.Fatalf("EventTypes len: want 3 got %d", len(types))
	}
}
