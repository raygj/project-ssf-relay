package relay

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// SigningKey holds a loaded ECDSA P-256 private key and its JWK-thumbprint kid.
// SETs signed with this key carry typ=secevent+jwt, alg=ES256, kid=<thumbprint>
// and can be verified via the JWKS built from PublicJWK.
type SigningKey struct {
	PrivateKey *ecdsa.PrivateKey
	KID        string
	PublicJWK  []byte // JSON-encoded public JWK for operator reference / JWKS exposure
}

// LoadSigningKeyFromPEM parses a PEM-encoded EC PRIVATE KEY block and computes
// the JWK thumbprint (SHA-256) as the kid — the same algorithm used by the plugin.
func LoadSigningKeyFromPEM(pemData []byte) (*SigningKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("signing key: no PEM block found")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: parse EC private key: %w", err)
	}

	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing key: compute JWK thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumb)
	jwk.KeyID = kid

	pubJWKBytes, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("signing key: marshal public JWK: %w", err)
	}

	return &SigningKey{
		PrivateKey: privKey,
		KID:        kid,
		PublicJWK:  pubJWKBytes,
	}, nil
}

// SignSET produces a compact JWS (RFC 7515) for the SET.
// The JOSE header contains: alg=ES256, typ=secevent+jwt, kid=<thumbprint>.
// The payload is the JSON-encoded SET struct.
func SignSET(set SET, sk *SigningKey) (string, error) {
	payload, err := json.Marshal(set)
	if err != nil {
		return "", fmt.Errorf("sign SET: marshal payload: %w", err)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: sk.PrivateKey},
		(&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", sk.KID),
	)
	if err != nil {
		return "", fmt.Errorf("sign SET: create signer: %w", err)
	}

	jws, err := sig.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign SET: sign: %w", err)
	}
	return jws.CompactSerialize()
}
