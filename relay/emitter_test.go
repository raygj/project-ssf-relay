package relay

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// captureReceiver starts a test HTTP server that records the last request.
type captureReceiver struct {
	server      *httptest.Server
	contentType string
	body        []byte
}

func newCaptureReceiver() *captureReceiver {
	cr := &captureReceiver{}
	cr.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cr.contentType = r.Header.Get("Content-Type")
		cr.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	return cr
}

func testEvent() Event {
	return Event{
		Type:          "https://schemas.fiam/vault/secret-accessed",
		CorrelationID: "corr-1",
		Subject:       Subject{EntityID: "ent-1", EntityName: "workload-a"},
		Metadata:      map[string]string{"secret_path": "secret/data/prod"},
	}
}

func TestEmitter_UnsignedDelivery(t *testing.T) {
	cr := newCaptureReceiver()
	defer cr.server.Close()

	emitter := NewEmitter(cr.server.URL, "ssf-relay", 5, nil)
	if err := emitter.Emit("vault-prod", testEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if cr.contentType != "application/json" {
		t.Errorf("Content-Type: want application/json got %q", cr.contentType)
	}

	// Body should be valid JSON containing the SET fields.
	var got map[string]interface{}
	if err := json.Unmarshal(cr.body, &got); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if got["iss"] != "ssf-relay" {
		t.Errorf("iss: want ssf-relay got %v", got["iss"])
	}
	if _, ok := got["jti"]; !ok {
		t.Error("missing jti")
	}
}

func TestEmitter_SignedDelivery_ContentType(t *testing.T) {
	cr := newCaptureReceiver()
	defer cr.server.Close()

	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	emitter := NewEmitter(cr.server.URL, "ssf-relay", 5, sk)
	if err := emitter.Emit("vault-prod", testEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	if cr.contentType != "application/secevent+jwt" {
		t.Errorf("Content-Type: want application/secevent+jwt got %q", cr.contentType)
	}
}

func TestEmitter_SignedDelivery_CompactJWS(t *testing.T) {
	cr := newCaptureReceiver()
	defer cr.server.Close()

	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	emitter := NewEmitter(cr.server.URL, "ssf-relay", 5, sk)
	if err := emitter.Emit("vault-prod", testEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	token := strings.TrimSpace(string(cr.body))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWS (3 parts), got %d: %q", len(parts), token)
	}
}

func TestEmitter_SignedDelivery_Verifiable(t *testing.T) {
	cr := newCaptureReceiver()
	defer cr.server.Close()

	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	emitter := NewEmitter(cr.server.URL, "ssf-relay", 5, sk)
	if err := emitter.Emit("vault-prod", testEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var pubJWK jose.JSONWebKey
	if err := json.Unmarshal(sk.PublicJWK, &pubJWK); err != nil {
		t.Fatalf("parse public JWK: %v", err)
	}

	token := strings.TrimSpace(string(cr.body))
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWS: %v", err)
	}
	payload, err := jws.Verify(pubJWK.Key)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}

	var set SET
	if err := json.Unmarshal(payload, &set); err != nil {
		t.Fatalf("unmarshal SET: %v", err)
	}
	if set.Issuer != "ssf-relay" {
		t.Errorf("iss: want ssf-relay got %q", set.Issuer)
	}
	if set.Source != "vault-prod" {
		t.Errorf("source: want vault-prod got %q", set.Source)
	}
}

func TestEmitter_SignedDelivery_KIDInHeader(t *testing.T) {
	cr := newCaptureReceiver()
	defer cr.server.Close()

	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	emitter := NewEmitter(cr.server.URL, "ssf-relay", 5, sk)
	if err := emitter.Emit("vault-prod", testEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	token := strings.TrimSpace(string(cr.body))
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWS: %v", err)
	}
	if jws.Signatures[0].Header.KeyID != sk.KID {
		t.Errorf("kid mismatch: want %q got %q", sk.KID, jws.Signatures[0].Header.KeyID)
	}
}

func TestEmitter_ReceiverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	emitter := NewEmitter(srv.URL, "ssf-relay", 5, nil)
	err := emitter.Emit("src", testEvent())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
