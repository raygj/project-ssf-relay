// Package webhook implements a generic inbound ActionAdapter that POSTs the
// inbound SSF SET as JSON to a configured HTTP endpoint.
//
// Handles all three CAEP event types by default. The receiving system
// differentiates by the event_type field in the posted body.
//
// Config keys:
//
//	url          (string, required) Endpoint to POST to.
//	headers      (map[string]string) Extra HTTP headers (e.g. Authorization).
//	timeout_secs (int) Request timeout. Default: 10.
//	event_types  ([]string) Limit to specific event types. Default: all three CAEP types.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	actions.Register("webhook", func(cfg map[string]interface{}) (relay.ActionAdapter, error) {
		return NewAdapter(cfg)
	})
}

// Adapter POSTs inbound SETs as JSON to a configured HTTP endpoint.
type Adapter struct {
	url        string
	headers    map[string]string
	eventTypes []string
	client     *http.Client
}

// NewAdapter constructs a webhook Adapter from a config map.
func NewAdapter(cfg map[string]interface{}) (*Adapter, error) {
	a := &Adapter{
		headers:    map[string]string{},
		eventTypes: []string{eventCompromised, eventDegraded, eventRecovered},
	}

	url, ok := cfg["url"].(string)
	if !ok || url == "" {
		return nil, fmt.Errorf("webhook: url is required")
	}
	a.url = url

	if v, ok := cfg["headers"]; ok {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("webhook: marshal headers: %w", err)
		}
		if err := json.Unmarshal(raw, &a.headers); err != nil {
			return nil, fmt.Errorf("webhook: parse headers: %w", err)
		}
	}

	timeout := 10 * time.Second
	if v, ok := cfg["timeout_secs"]; ok {
		switch n := v.(type) {
		case int:
			timeout = time.Duration(n) * time.Second
		case float64:
			timeout = time.Duration(int(n)) * time.Second
		}
	}

	if v, ok := cfg["event_types"]; ok {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("webhook: marshal event_types: %w", err)
		}
		if err := json.Unmarshal(raw, &a.eventTypes); err != nil {
			return nil, fmt.Errorf("webhook: parse event_types: %w", err)
		}
	}

	a.client = &http.Client{Timeout: timeout}
	return a, nil
}

func (a *Adapter) Name() string         { return "webhook" }
func (a *Adapter) EventTypes() []string { return a.eventTypes }

// Act POSTs the inbound SET as JSON to the configured URL.
func (a *Adapter) Act(ctx context.Context, set relay.InboundSET) error {
	body, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("webhook: marshal SET: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST %s: %w", a.url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook POST %s: HTTP %d", a.url, resp.StatusCode)
	}
	return nil
}
