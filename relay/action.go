package relay

import "context"

// InboundSET is the JSON payload received on the trust-receiver SSE stream.
// Field names match the receivedSET struct published by ssf-trust-receiver.
type InboundSET struct {
	EventType     string         `json:"event_type"`
	SourceID      string         `json:"source_id,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
}

// ActionAdapter translates an inbound SSF SET into a local system action.
// Implementations live under actions/<system>/adapter.go.
type ActionAdapter interface {
	Name() string
	EventTypes() []string
	Act(ctx context.Context, set InboundSET) error
}
