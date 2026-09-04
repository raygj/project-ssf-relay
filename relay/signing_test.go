package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// generateTestPEM creates an in-memory ECDSA P-256 PEM for tests.
func generateTestPEM(t *testing.T) []byte {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestLoadSigningKeyFromPEM_Valid(t *testing.T) {
	pemData := generateTestPEM(t)
	sk, err := LoadSigningKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sk.KID == "" {
		t.Error("expected non-empty KID")
	}
	if sk.PrivateKey == nil {
		t.Error("expected non-nil private key")
	}
	if len(sk.PublicJWK) == 0 {
		t.Error("expected non-empty public JWK")
	}
	// KID should be base64url, no padding.
	if strings.Contains(sk.KID, "=") {
		t.Errorf("KID should be raw base64url (no padding): %q", sk.KID)
	}
}

func TestLoadSigningKeyFromPEM_InvalidBytes(t *testing.T) {
	_, err := LoadSigningKeyFromPEM([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadSigningKeyFromPEM_WrongKeyType(t *testing.T) {
	// RSA key should fail the EC parse step.
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")}
	bad := pem.EncodeToMemory(block)
	_, err := LoadSigningKeyFromPEM(bad)
	if err == nil {
		t.Fatal("expected error for malformed key bytes")
	}
}

func TestLoadSigningKeyFromPEM_KIDIsDeterministic(t *testing.T) {
	pemData := generateTestPEM(t)
	k1, err := LoadSigningKeyFromPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadSigningKeyFromPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if k1.KID != k2.KID {
		t.Errorf("KID should be deterministic: %q vs %q", k1.KID, k2.KID)
	}
}

func TestSignSET_ProducesCompactJWS(t *testing.T) {
	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	set := SET{
		Issuer:        "ssf-relay",
		IssuedAt:      time.Now().Unix(),
		JWTID:         "set-test-1",
		CorrelationID: "corr-abc",
		Source:        "vault-prod",
		Events:        map[string]interface{}{"https://schemas.fiam/vault/secret-accessed": map[string]string{"path": "secret/data/foo"}},
	}

	token, err := SignSET(set, sk)
	if err != nil {
		t.Fatalf("SignSET: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 compact JWS parts, got %d", len(parts))
	}
}

func TestSignSET_HeaderHasKidAndTyp(t *testing.T) {
	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	set := SET{Issuer: "ssf-relay", IssuedAt: time.Now().Unix(), JWTID: "j1", Source: "s"}
	token, err := SignSET(set, sk)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWS: %v", err)
	}
	if len(jws.Signatures) == 0 {
		t.Fatal("no signatures")
	}
	hdr := jws.Signatures[0].Header
	if hdr.KeyID != sk.KID {
		t.Errorf("kid: want %q got %q", sk.KID, hdr.KeyID)
	}
	if hdr.ExtraHeaders["typ"] != "secevent+jwt" {
		t.Errorf("typ: want secevent+jwt got %v", hdr.ExtraHeaders["typ"])
	}
}

func TestSignSET_VerifiableWithPublicKey(t *testing.T) {
	sk, err := LoadSigningKeyFromPEM(generateTestPEM(t))
	if err != nil {
		t.Fatal(err)
	}

	set := SET{
		Issuer:        "ssf-relay",
		IssuedAt:      time.Now().Unix(),
		JWTID:         "set-verify",
		CorrelationID: "corr-xyz",
		Source:        "vault-prod",
		Events:        map[string]interface{}{"https://schemas.fiam/vault/credential-issued": map[string]string{"path": "pki/issue/web"}},
	}

	token, err := SignSET(set, sk)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Parse the public JWK and verify.
	var pubJWK jose.JSONWebKey
	if err := json.Unmarshal(sk.PublicJWK, &pubJWK); err != nil {
		t.Fatalf("parse public JWK: %v", err)
	}

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse JWS: %v", err)
	}
	payload, err := jws.Verify(pubJWK.Key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	var got SET
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.JWTID != set.JWTID {
		t.Errorf("jti mismatch: want %q got %q", set.JWTID, got.JWTID)
	}
	if got.CorrelationID != set.CorrelationID {
		t.Errorf("correlation_id mismatch: want %q got %q", set.CorrelationID, got.CorrelationID)
	}
}
