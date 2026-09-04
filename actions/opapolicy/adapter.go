// Package opapolicy implements the inbound ActionAdapter for OPA policy injection.
//
// On source-compromised: PUTs a deny-all Rego policy for the affected source.
// On source-degraded:    PUTs a warn/restrict Rego policy for the affected source.
// On source-recovered:   DELETEs the injected policy, restoring normal evaluation.
//
// Uses the OPA Management API (PUT/DELETE /v1/policies/{id}).
//
// Config keys:
//
//	opa_addr          (string) OPA server base URL. Default: http://localhost:8181
//	policy_id_prefix  (string) Prefix for injected policy IDs. Default: ssf-relay
//	compromised_rego  (string) Rego to inject on source-compromised. Uses default if empty.
//	degraded_rego     (string) Rego to inject on source-degraded. Uses default if empty.
package opapolicy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/raygj/ssf-relay/actions"
	"github.com/raygj/ssf-relay/relay"
)

const (
	eventCompromised = "https://schemas.openid.net/secevent/caep/event-type/source-compromised"
	eventDegraded    = "https://schemas.openid.net/secevent/caep/event-type/source-degraded"
	eventRecovered   = "https://schemas.openid.net/secevent/caep/event-type/source-recovered"

	// defaultCompromisedRego denies all requests that carry the compromised source ID.
	defaultCompromisedRego = `package ssf.relay.quarantine.{{.PackageID}}

# Auto-injected by ssf-relay — source-compromised signal
# source:     {{.SourceID}}
# event_type: {{.EventType}}
# reason:     {{.Reason}}

default allow := false

deny contains msg if {
    input.source == "{{.SourceID}}"
    msg := "source {{.SourceID}} quarantined by SSF fabric (compromised)"
}
`

	// defaultDegradedRego adds a metadata flag without hard-denying.
	defaultDegradedRego = `package ssf.relay.degraded.{{.PackageID}}

# Auto-injected by ssf-relay — source-degraded signal
# source:     {{.SourceID}}
# event_type: {{.EventType}}
# reason:     {{.Reason}}

# Adds a warning annotation; does not deny. Consuming policies may check
# data.ssf.relay.degraded[id].degraded == true.
degraded := true
source_id := "{{.SourceID}}"
`
)

// safeID converts an arbitrary string into a valid Rego identifier segment.
// Rego package path components must be valid identifiers: [a-zA-Z_][a-zA-Z0-9_]*
var safeID = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func init() {
	actions.Register("opa-policy", func(cfg map[string]interface{}) (relay.ActionAdapter, error) {
		return NewAdapter(cfg)
	})
}

// Adapter injects or removes OPA policies in response to CAEP signals.
type Adapter struct {
	opaAddr         string
	policyIDPrefix  string
	compromisedRego string
	degradedRego    string
	client          *http.Client
}

// NewAdapter constructs an opa-policy Adapter from a config map.
func NewAdapter(cfg map[string]interface{}) (*Adapter, error) {
	a := &Adapter{
		opaAddr:         "http://localhost:8181",
		policyIDPrefix:  "ssf-relay",
		compromisedRego: defaultCompromisedRego,
		degradedRego:    defaultDegradedRego,
		client:          &http.Client{Timeout: 10 * time.Second},
	}
	if v, ok := cfg["opa_addr"].(string); ok && v != "" {
		a.opaAddr = strings.TrimRight(v, "/")
	}
	if v, ok := cfg["policy_id_prefix"].(string); ok && v != "" {
		a.policyIDPrefix = v
	}
	if v, ok := cfg["compromised_rego"].(string); ok && v != "" {
		a.compromisedRego = v
	}
	if v, ok := cfg["degraded_rego"].(string); ok && v != "" {
		a.degradedRego = v
	}
	return a, nil
}

func (a *Adapter) Name() string { return "opa-policy" }

func (a *Adapter) EventTypes() []string {
	return []string{eventCompromised, eventDegraded, eventRecovered}
}

// Act dispatches the inbound SET to policy inject or delete.
func (a *Adapter) Act(ctx context.Context, set relay.InboundSET) error {
	switch set.EventType {
	case eventCompromised:
		return a.putPolicy(ctx, set, "compromised", a.compromisedRego)
	case eventDegraded:
		return a.putPolicy(ctx, set, "degraded", a.degradedRego)
	case eventRecovered:
		// Remove both compromised and degraded policies if present.
		e1 := a.deletePolicy(ctx, a.policyID(set.SourceID, "compromised"))
		e2 := a.deletePolicy(ctx, a.policyID(set.SourceID, "degraded"))
		return joinErrs(e1, e2)
	default:
		return fmt.Errorf("opa-policy: unhandled event type %q", set.EventType)
	}
}

// policyID returns a deterministic OPA policy ID for a source + state pair.
func (a *Adapter) policyID(sourceID, state string) string {
	safe := safeID.ReplaceAllString(sourceID, "_")
	return fmt.Sprintf("%s_%s_%s", a.policyIDPrefix, safe, state)
}

// putPolicy renders the Rego template and PUTs it to OPA.
func (a *Adapter) putPolicy(ctx context.Context, set relay.InboundSET, state, regoTmpl string) error {
	id := a.policyID(set.SourceID, state)

	reason := set.Reason
	if reason == "" {
		if set.Payload != nil {
			if v, ok := set.Payload["reason"].(string); ok {
				reason = v
			}
		}
	}

	data := struct {
		PolicyID  string // used in OPA API URL — may contain dashes
		PackageID string // used in Rego package path — dashes replaced with underscores
		SourceID  string
		EventType string
		Reason    string
	}{
		PolicyID:  id,
		PackageID: safeID.ReplaceAllString(id, "_"),
		SourceID:  set.SourceID,
		EventType: set.EventType,
		Reason:    reason,
	}

	tmpl, err := template.New("rego").Parse(regoTmpl)
	if err != nil {
		return fmt.Errorf("opa-policy: parse rego template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("opa-policy: render rego template: %w", err)
	}

	url := fmt.Sprintf("%s/v1/policies/%s", a.opaAddr, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, &buf)
	if err != nil {
		return fmt.Errorf("build PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("PUT policy/%s: %w", id, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("PUT policy/%s: HTTP %d", id, resp.StatusCode)
	}
	return nil
}

// deletePolicy DELETEs a policy from OPA. 404 is treated as success.
func (a *Adapter) deletePolicy(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/v1/policies/%s", a.opaAddr, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("build DELETE request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE policy/%s: %w", id, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone — idempotent
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("DELETE policy/%s: HTTP %d", id, resp.StatusCode)
	}
	return nil
}

func joinErrs(errs ...error) error {
	var msgs []string
	for _, err := range errs {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}
