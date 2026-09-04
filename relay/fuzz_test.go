package relay

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// FuzzInboundSET exercises the inbound wire path: the JSON decode of an SSE
// "data:" payload into InboundSET, followed by routing. This mirrors the decode
// in Subscriber.readSSE. Untrusted bytes from the trust-receiver stream must
// never panic; an undecodable payload is dropped, and an unrouted event type is
// a no-op.
func FuzzInboundSET(f *testing.F) {
	seeds := []string{
		`{"event_type":"https://schemas.openid.net/secevent/caep/event-type/source-compromised","source_id":"vault-prod","correlation_id":"c-1","reason":"trust ring eviction","payload":{"entity_id":"ent-1"}}`,
		`{"event_type":"https://schemas.openid.net/secevent/caep/event-type/source-degraded"}`,
		`{"payload":{"nested":{"a":[1,2,3]}}}`,
		`{}`,
		``,
		`not json`,
		`{"event_type":123}`,
		`{"payload":"not-an-object"}`,
		`{"event_type":"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	r := NewRouter(hclog.NewNullLogger())
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, payload string) {
		var set InboundSET
		if err := json.Unmarshal([]byte(payload), &set); err != nil {
			return // matches readSSE: undecodable payloads are dropped
		}
		_ = r.Handle(ctx, set)
	})
}
