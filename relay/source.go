package relay

// Source is the only interface a log adapter must implement.
// It knows nothing about file tailing, SET building, or HTTP.
type Source interface {
	Name() string
	Parse(line string) (Event, bool)
}

// Event is everything the core needs to build a SET.
// Source-specific fields go in Metadata — core never inspects them.
type Event struct {
	Type          string // SSF event URI (required)
	CorrelationID string // per-request trace ID
	Subject       Subject
	Metadata      map[string]string // all land in SET payload verbatim
}

// Subject carries identity fields extracted from the log line.
type Subject struct {
	EntityID   string `json:"entity_id,omitempty"`
	EntityName string `json:"entity_name,omitempty"`
	Accessor   string `json:"accessor,omitempty"`
}
