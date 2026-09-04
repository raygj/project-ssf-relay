package vault

import "testing"

// FuzzParse exercises the Vault audit-log parser against arbitrary wire input.
// Parse handles untrusted log lines from a system audit device; it must never
// panic, only return (Event, false) on anything it cannot classify.
func FuzzParse(f *testing.F) {
	seeds := []string{
		`{"type":"response","request":{"id":"req-1","path":"database/creds/my-role","operation":"read","entity_id":"ent-1"},"auth":{"token_accessor":"acc-1","display_name":"u1","entity_id":"ent-1"},"response":{"secret":{"lease_id":"lease-1","lease_duration":3600}},"error":""}`,
		`{"type":"request","request":{"path":"sys/health","id":"r","operation":"read"}}`,
		`{"type":"response","request":{"path":"kv/data/app","operation":"read"},"error":"permission denied"}`,
		`{"type":"response"}`,
		`{}`,
		``,
		`not json`,
		`{"type":"response","request":null,"auth":null,"response":null}`,
		`{"request":{"path":"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	s := newTestSource()
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = s.Parse(line)
	})
}
