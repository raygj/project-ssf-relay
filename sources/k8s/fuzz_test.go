package k8s

import "testing"

// FuzzParse exercises the Kubernetes audit-log parser against arbitrary wire
// input. Parse handles untrusted audit.k8s.io/v1 lines; it must never panic,
// only return (Event, false) on anything it cannot classify.
func FuzzParse(f *testing.F) {
	seeds := []string{
		`{"kind":"Event","apiVersion":"audit.k8s.io/v1","stage":"ResponseComplete","verb":"get","user":{"username":"alice"},"objectRef":{"resource":"secrets","name":"db","namespace":"prod"},"responseStatus":{"code":200}}`,
		`{"stage":"ResponseComplete","verb":"watch","user":{"username":"system:node"},"objectRef":{"resource":"pods"}}`,
		`{"stage":"ResponseComplete","verb":"get","objectRef":{"resource":"secrets"},"responseStatus":{"code":403}}`,
		`{"stage":"RequestReceived"}`,
		`{}`,
		``,
		`not json`,
		`{"user":null,"objectRef":null,"responseStatus":null}`,
		`{"objectRef":{"resource":"`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	s := newTestSource()
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = s.Parse(line)
	})
}
