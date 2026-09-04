package relay

// SET is the wire format for a Security Event Token (RFC 8417).
// It is compatible with the ssf-trust-receiver SET struct, with
// relay-specific extensions for correlation_id and source.
type SET struct {
	Issuer        string                 `json:"iss"`
	IssuedAt      int64                  `json:"iat"`
	JWTID         string                 `json:"jti"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	Source        string                 `json:"source"`
	Events        map[string]interface{} `json:"events"`
}
