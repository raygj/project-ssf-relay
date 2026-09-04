package opa

import "testing"

// FuzzParse exercises the OPA decision-log parser against arbitrary wire input.
// Parse handles untrusted decision-log lines; it must never panic, only return
// (Event, false) on anything it cannot classify.
func FuzzParse(f *testing.F) {
	seeds := []string{
		`{"decision_id":"d-1","path":"authz/allow","result":false,"input":{"user":"alice"}}`,
		`{"decision_id":"d-2","path":"authz/allow","result":true}`,
		`{"path":"data.system.main","result":true}`,
		`{"result":false}`,
		`{}`,
		``,
		`not json`,
		`{"result":null,"input":null}`,
		`{"path":"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// emitAllow=true so both allow and deny paths are exercised.
	s := newTestSource(true)
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = s.Parse(line)
	})
}
