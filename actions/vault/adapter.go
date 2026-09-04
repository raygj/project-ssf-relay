// Package vault implements the inbound ActionAdapter for Vault.
//
// On source-compromised: revokes the relay's own Vault token (self-isolation).
// On source-degraded:    sets metadata ssf_status=degraded on the relay entity.
// On source-recovered:   clears the ssf_status metadata flag.
//
// Config keys:
//
//	vault_addr      (string)  Vault server base URL. Default: http://127.0.0.1:8200
//	vault_token_env (string)  Env var holding the Vault token. Default: VAULT_TOKEN
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/raygj/ssf-relay/actions"
	"github.com/raygj/ssf-relay/relay"
)

const (
	eventCompromised = "https://schemas.openid.net/secevent/caep/event-type/source-compromised"
	eventDegraded    = "https://schemas.openid.net/secevent/caep/event-type/source-degraded"
	eventRecovered   = "https://schemas.openid.net/secevent/caep/event-type/source-recovered"
)

func init() {
	actions.Register("vault", func(cfg map[string]interface{}) (relay.ActionAdapter, error) {
		return NewAdapter(cfg)
	})
}

// Adapter translates inbound CAEP signals into Vault API calls.
type Adapter struct {
	vaultAddr string
	tokenEnv  string
	client    *http.Client
}

// NewAdapter constructs a vault Adapter from a config map.
func NewAdapter(cfg map[string]interface{}) (*Adapter, error) {
	a := &Adapter{
		vaultAddr: "http://127.0.0.1:8200",
		tokenEnv:  "VAULT_TOKEN",
		client:    &http.Client{Timeout: 10 * time.Second},
	}
	if v, ok := cfg["vault_addr"].(string); ok && v != "" {
		a.vaultAddr = strings.TrimRight(v, "/")
	}
	if v, ok := cfg["vault_token_env"].(string); ok && v != "" {
		a.tokenEnv = v
	}
	return a, nil
}

func (a *Adapter) Name() string { return "vault" }

func (a *Adapter) EventTypes() []string {
	return []string{eventCompromised, eventDegraded, eventRecovered}
}

// Act dispatches the inbound SET to the appropriate Vault API call.
func (a *Adapter) Act(ctx context.Context, set relay.InboundSET) error {
	switch set.EventType {
	case eventCompromised:
		return a.revokeself(ctx, set)
	case eventDegraded:
		return a.flagEntity(ctx, set, "degraded")
	case eventRecovered:
		return a.flagEntity(ctx, set, "")
	default:
		return fmt.Errorf("vault adapter: unhandled event type %q", set.EventType)
	}
}

// revokeself calls POST /v1/auth/token/revoke-self to kill this relay's Vault session.
// This is the self-isolation response to a source-compromised signal.
func (a *Adapter) revokeself(ctx context.Context, set relay.InboundSET) error {
	token := os.Getenv(a.tokenEnv)
	if token == "" {
		return fmt.Errorf("vault: env %q is empty — cannot revoke", a.tokenEnv)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.vaultAddr+"/v1/auth/token/revoke-self", nil)
	if err != nil {
		return fmt.Errorf("build revoke-self request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST revoke-self: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusForbidden {
		// 403 means token is already invalid (revoked or root token restriction).
		// Either way the Vault session is inaccessible — goal achieved.
		return nil
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST revoke-self: HTTP %d", resp.StatusCode)
	}
	return nil
}

// flagEntity sets or clears the ssf_status metadata on the relay's Vault entity.
// status="" clears the flag (source-recovered); otherwise sets it (source-degraded).
func (a *Adapter) flagEntity(ctx context.Context, set relay.InboundSET, status string) error {
	token := os.Getenv(a.tokenEnv)
	if token == "" {
		return fmt.Errorf("vault: env %q is empty — cannot flag entity", a.tokenEnv)
	}

	entityID, err := a.lookupEntityID(ctx, token)
	if err != nil {
		return fmt.Errorf("lookup entity: %w", err)
	}
	if entityID == "" {
		// Token has no associated entity (e.g. root token) — nothing to flag.
		return nil
	}

	metadata := map[string]string{
		"ssf_status":         status,
		"ssf_source_id":      set.SourceID,
		"ssf_event_type":     set.EventType,
		"ssf_correlation_id": set.CorrelationID,
	}
	if status == "" {
		// Clearing: remove SSF keys by setting empty strings.
		metadata["ssf_status"] = ""
		metadata["ssf_source_id"] = ""
	}

	body, _ := json.Marshal(map[string]any{"metadata": metadata})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.vaultAddr+"/v1/identity/entity/id/"+entityID, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build entity update request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST entity/id/%s: %w", entityID, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("POST entity/id/%s: HTTP %d", entityID, resp.StatusCode)
	}
	return nil
}

// lookupEntityID calls GET /v1/auth/token/lookup-self and returns the entity_id.
func (a *Adapter) lookupEntityID(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.vaultAddr+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return "", fmt.Errorf("build lookup-self request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET lookup-self: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// Token already invalid — no entity to look up.
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET lookup-self: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			EntityID string `json:"entity_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode lookup-self: %w", err)
	}
	return result.Data.EntityID, nil
}
