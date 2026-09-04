// Package k8scordon implements the inbound ActionAdapter for Kubernetes node cordoning.
//
// On source-compromised: cordons the node (unschedulable=true) — no new pods scheduled.
// On source-degraded:    cordons the node (treat degraded node as unsafe for new workloads).
// On source-recovered:   uncordons the node (unschedulable=false).
//
// Uses the raw Kubernetes API via the in-cluster service account token.
// No client-go dependency required.
//
// Config keys:
//
//	node_name      (string) Static node name. Takes precedence over node_name_env.
//	node_name_env  (string) Env var holding the node name. Default: NODE_NAME.
//	                        Inject with the downward API (spec.nodeName).
//	kubeapi        (string) Kubernetes API server URL. Default: https://kubernetes.default.svc
//	token_file     (string) Path to service account token. Default: in-cluster path.
//	ca_file        (string) Path to CA bundle. Default: in-cluster path.
package k8scordon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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

	defaultKubeAPI   = "https://kubernetes.default.svc"
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func init() {
	actions.Register("k8s-cordon", func(cfg map[string]interface{}) (relay.ActionAdapter, error) {
		return NewAdapter(cfg)
	})
}

// Adapter cordons or uncordons a Kubernetes node in response to CAEP signals.
type Adapter struct {
	nodeName    string // static; overrides env lookup
	nodeNameEnv string
	kubeAPI     string
	tokenFile   string
	caFile      string
	client      *http.Client
}

// NewAdapter constructs a k8s-cordon Adapter from a config map.
func NewAdapter(cfg map[string]interface{}) (*Adapter, error) {
	a := &Adapter{
		nodeNameEnv: "NODE_NAME",
		kubeAPI:     defaultKubeAPI,
		tokenFile:   defaultTokenFile,
		caFile:      defaultCAFile,
	}
	if v, ok := cfg["node_name"].(string); ok && v != "" {
		a.nodeName = v
	}
	if v, ok := cfg["node_name_env"].(string); ok && v != "" {
		a.nodeNameEnv = v
	}
	if v, ok := cfg["kubeapi"].(string); ok && v != "" {
		a.kubeAPI = strings.TrimRight(v, "/")
	}
	if v, ok := cfg["token_file"].(string); ok && v != "" {
		a.tokenFile = v
	}
	if v, ok := cfg["ca_file"].(string); ok && v != "" {
		a.caFile = v
	}

	client, err := buildClient(a.caFile)
	if err != nil {
		return nil, fmt.Errorf("k8s-cordon: build HTTP client: %w", err)
	}
	a.client = client
	return a, nil
}

func (a *Adapter) Name() string { return "k8s-cordon" }

func (a *Adapter) EventTypes() []string {
	return []string{eventCompromised, eventDegraded, eventRecovered}
}

// Act dispatches the inbound SET to cordon or uncordon.
func (a *Adapter) Act(ctx context.Context, set relay.InboundSET) error {
	node, err := a.resolveNode(set)
	if err != nil {
		return err
	}

	switch set.EventType {
	case eventCompromised, eventDegraded:
		return a.setCordon(ctx, node, true)
	case eventRecovered:
		return a.setCordon(ctx, node, false)
	default:
		return fmt.Errorf("k8s-cordon: unhandled event type %q", set.EventType)
	}
}

// resolveNode returns the node name from config, env, or SET payload.
// Priority: static node_name config > node_name_env > payload["node_name"].
func (a *Adapter) resolveNode(set relay.InboundSET) (string, error) {
	if a.nodeName != "" {
		return a.nodeName, nil
	}
	if name := os.Getenv(a.nodeNameEnv); name != "" {
		return name, nil
	}
	// Fall back to payload field "node_name" if present.
	if set.Payload != nil {
		if v, ok := set.Payload["node_name"].(string); ok && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("k8s-cordon: cannot determine node name — set node_name config or %s env var", a.nodeNameEnv)
}

// setCordon PATCHes the node's spec.unschedulable field.
func (a *Adapter) setCordon(ctx context.Context, node string, unschedulable bool) error {
	token, err := os.ReadFile(a.tokenFile)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	patch, _ := json.Marshal(map[string]any{
		"spec": map[string]any{"unschedulable": unschedulable},
	})

	url := fmt.Sprintf("%s/api/v1/nodes/%s", a.kubeAPI, node)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(patch))
	if err != nil {
		return fmt.Errorf("build PATCH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("PATCH node/%s: %w", node, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("PATCH node/%s: HTTP %d", node, resp.StatusCode)
	}
	return nil
}

// buildClient returns an HTTP client that trusts the cluster CA.
// Falls back to system roots if the CA file is missing (e.g. local dev run).
func buildClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{}
	if caData, err := os.ReadFile(caFile); err == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("no certificates parsed from %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	// caFile missing → use system roots (dev/testing outside cluster).
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}
