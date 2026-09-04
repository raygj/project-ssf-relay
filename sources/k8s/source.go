package k8s

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/raygj/ssf-relay/relay"
	"github.com/raygj/ssf-relay/sources"
)

func init() {
	sources.Register("k8s-audit", func(cfg map[string]interface{}) (relay.Source, error) {
		return NewSource(cfg)
	})
}

// Source parses Kubernetes audit log JSON lines into relay.Events.
type Source struct {
	stages    map[string]bool
	dropUsers map[string]bool
	dropVerbs map[string]bool
}

// NewSource constructs a k8s audit Source from a config map.
func NewSource(cfg map[string]interface{}) (*Source, error) {
	s := &Source{
		stages:    map[string]bool{"ResponseComplete": true},
		dropUsers: map[string]bool{},
		dropVerbs: map[string]bool{},
	}

	if v, ok := cfg["stages"]; ok {
		stages, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("k8s source: stages: %w", err)
		}
		s.stages = map[string]bool{}
		for _, st := range stages {
			s.stages[st] = true
		}
	}

	if v, ok := cfg["drop_users"]; ok {
		users, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("k8s source: drop_users: %w", err)
		}
		for _, u := range users {
			s.dropUsers[u] = true
		}
	}

	if v, ok := cfg["drop_verbs"]; ok {
		verbs, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("k8s source: drop_verbs: %w", err)
		}
		for _, verb := range verbs {
			s.dropVerbs[verb] = true
		}
	}

	return s, nil
}

func (s *Source) Name() string { return "k8s-audit" }

// k8sAuditEvent is the subset of the audit.k8s.io/v1 Event we care about.
type k8sAuditEvent struct {
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string `json:"username"`
		UID      string `json:"uid"`
	} `json:"user"`
	SourceIPs []string `json:"sourceIPs"`
	ObjectRef struct {
		Resource   string `json:"resource"`
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		APIVersion string `json:"apiVersion"`
	} `json:"objectRef"`
	ResponseStatus struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
}

// Parse implements relay.Source.
func (s *Source) Parse(line string) (relay.Event, bool) {
	var entry k8sAuditEvent
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return relay.Event{}, false
	}

	// Filter by stage.
	if !s.stages[entry.Stage] {
		return relay.Event{}, false
	}

	// Filter by user.
	username := entry.User.Username
	for dropUser := range s.dropUsers {
		if username == dropUser || strings.HasPrefix(username, dropUser) {
			return relay.Event{}, false
		}
	}

	// Filter by verb.
	if s.dropVerbs[entry.Verb] {
		return relay.Event{}, false
	}

	code := entry.ResponseStatus.Code
	verb := entry.Verb
	resource := entry.ObjectRef.Resource

	// Classify event type.
	var eventType string
	switch {
	case code == 401 || code == 403:
		eventType = "https://schemas.fiam/relay/k8s/secret-denied"
	case (verb == "get" || verb == "create") && (resource == "secrets" || resource == "configmaps") && code >= 200 && code < 300:
		eventType = "https://schemas.fiam/relay/k8s/secret-accessed"
	case verb == "create" && (resource == "serviceaccounts/token" || resource == "tokens") && code >= 200 && code < 300:
		eventType = "https://schemas.fiam/relay/k8s/credential-issued"
	case verb == "delete" && resource == "secrets" && code >= 200 && code < 300:
		eventType = "https://schemas.fiam/relay/k8s/credential-revoked"
	default:
		return relay.Event{}, false
	}

	// Extract service account identity if applicable.
	entityID := entry.User.UID
	entityName := username
	// Namespace extraction for service accounts.
	if strings.HasPrefix(username, "system:serviceaccount:") {
		parts := strings.SplitN(strings.TrimPrefix(username, "system:serviceaccount:"), ":", 2)
		if len(parts) == 2 {
			entityName = parts[1] // service account name
		}
	}

	remoteAddr := ""
	if len(entry.SourceIPs) > 0 {
		remoteAddr = entry.SourceIPs[0]
	}

	meta := map[string]string{
		"k8s_namespace":   entry.ObjectRef.Namespace,
		"k8s_resource":    resource,
		"k8s_name":        entry.ObjectRef.Name,
		"k8s_verb":        verb,
		"k8s_request_uri": entry.RequestURI,
		"remote_address":  remoteAddr,
		"response_code":   fmt.Sprintf("%d", code),
		"audit_id":        entry.AuditID,
	}

	return relay.Event{
		Type:          eventType,
		CorrelationID: entry.AuditID,
		Subject: relay.Subject{
			EntityID:   entityID,
			EntityName: entityName,
			Accessor:   entry.User.UID,
		},
		Metadata: meta,
	}, true
}

func toStringSlice(v interface{}) ([]string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
