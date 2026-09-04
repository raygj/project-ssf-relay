package k8s

import (
	"testing"
)

func newTestSource() *Source {
	s, _ := NewSource(map[string]interface{}{
		"stages": []interface{}{"ResponseComplete"},
		"drop_users": []interface{}{
			"system:node",
			"system:serviceaccount:kube-system:generic-garbage-collector",
		},
		"drop_verbs": []interface{}{"watch", "list"},
	})
	return s
}

const baseEvent = `{"auditID":"audit-1","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets/my-secret","verb":"get","user":{"username":"system:serviceaccount:default:my-app","uid":"uid-1"},"sourceIPs":["10.0.0.5"],"objectRef":{"resource":"secrets","namespace":"default","name":"my-secret","apiVersion":"v1"},"responseStatus":{"code":200}}`

func TestParse_SecretAccessed(t *testing.T) {
	s := newTestSource()
	ev, ok := s.Parse(baseEvent)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/k8s/secret-accessed" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
	if ev.Subject.EntityName != "my-app" {
		t.Errorf("expected service account name 'my-app', got %s", ev.Subject.EntityName)
	}
	if ev.Metadata["k8s_namespace"] != "default" {
		t.Errorf("unexpected namespace: %s", ev.Metadata["k8s_namespace"])
	}
	if ev.CorrelationID != "audit-1" {
		t.Errorf("unexpected correlation_id: %s", ev.CorrelationID)
	}
}

func TestParse_SecretDenied_403(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-2","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets/my-secret","verb":"get","user":{"username":"bob","uid":"uid-2"},"sourceIPs":["10.0.0.6"],"objectRef":{"resource":"secrets","namespace":"default","name":"my-secret","apiVersion":"v1"},"responseStatus":{"code":403}}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/k8s/secret-denied" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
}

func TestParse_CredentialIssued(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-3","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/serviceaccounts/my-app/token","verb":"create","user":{"username":"alice","uid":"uid-3"},"sourceIPs":["10.0.0.7"],"objectRef":{"resource":"serviceaccounts/token","namespace":"default","name":"my-app","apiVersion":"v1"},"responseStatus":{"code":201}}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/k8s/credential-issued" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
}

func TestParse_CredentialRevoked(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-4","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets/old-secret","verb":"delete","user":{"username":"alice","uid":"uid-4"},"sourceIPs":["10.0.0.8"],"objectRef":{"resource":"secrets","namespace":"default","name":"old-secret","apiVersion":"v1"},"responseStatus":{"code":200}}`
	ev, ok := s.Parse(line)
	if !ok {
		t.Fatal("expected event to be emitted")
	}
	if ev.Type != "https://schemas.fiam/relay/k8s/credential-revoked" {
		t.Errorf("unexpected type: %s", ev.Type)
	}
}

func TestParse_DropStage(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-5","stage":"RequestReceived","requestURI":"/api/v1/namespaces/default/secrets/my-secret","verb":"get","user":{"username":"alice","uid":"uid-5"},"sourceIPs":["10.0.0.9"],"objectRef":{"resource":"secrets","namespace":"default","name":"my-secret","apiVersion":"v1"},"responseStatus":{"code":200}}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected non-ResponseComplete stage to be dropped")
	}
}

func TestParse_DropUser(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-6","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets/my-secret","verb":"get","user":{"username":"system:node","uid":"uid-6"},"sourceIPs":["10.0.0.10"],"objectRef":{"resource":"secrets","namespace":"default","name":"my-secret","apiVersion":"v1"},"responseStatus":{"code":200}}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected system:node user to be dropped")
	}
}

func TestParse_DropVerb(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-7","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/secrets","verb":"watch","user":{"username":"alice","uid":"uid-7"},"sourceIPs":["10.0.0.11"],"objectRef":{"resource":"secrets","namespace":"default","name":"","apiVersion":"v1"},"responseStatus":{"code":200}}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected watch verb to be dropped")
	}
}

func TestParse_NoMatch(t *testing.T) {
	s := newTestSource()
	line := `{"auditID":"audit-8","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/default/pods/my-pod","verb":"get","user":{"username":"alice","uid":"uid-8"},"sourceIPs":["10.0.0.12"],"objectRef":{"resource":"pods","namespace":"default","name":"my-pod","apiVersion":"v1"},"responseStatus":{"code":200}}`
	_, ok := s.Parse(line)
	if ok {
		t.Error("expected pod GET to be dropped (no matching classification)")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := newTestSource()
	_, ok := s.Parse("not json at all")
	if ok {
		t.Error("expected invalid JSON to be dropped")
	}
}
