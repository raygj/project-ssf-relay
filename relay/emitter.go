package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Emitter builds SETs from Events and POSTs them to the configured receiver.
// When signingKey is non-nil, SETs are delivered as compact JWS
// (Content-Type: application/secevent+jwt); otherwise unsigned JSON is used.
type Emitter struct {
	receiverURL string
	issuer      string
	client      *http.Client
	signingKey  *SigningKey // nil = unsigned JSON
}

// NewEmitter creates an Emitter. Pass a nil signingKey for unsigned delivery.
func NewEmitter(receiverURL, issuer string, timeoutSecs int, signingKey *SigningKey) *Emitter {
	if timeoutSecs <= 0 {
		timeoutSecs = 5
	}
	return &Emitter{
		receiverURL: receiverURL,
		issuer:      issuer,
		signingKey:  signingKey,
		client: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
		},
	}
}

// Emit builds a SET from the given Event and source name, then POSTs it to the receiver.
func (e *Emitter) Emit(sourceName string, event Event) error {
	payload := map[string]interface{}{
		"entity_id":   event.Subject.EntityID,
		"entity_name": event.Subject.EntityName,
		"accessor":    event.Subject.Accessor,
	}
	for k, v := range event.Metadata {
		payload[k] = v
	}

	set := SET{
		Issuer:        e.issuer,
		IssuedAt:      time.Now().Unix(),
		JWTID:         "set-" + uuid.NewString(),
		CorrelationID: event.CorrelationID,
		Source:        sourceName,
		Events: map[string]interface{}{
			event.Type: payload,
		},
	}

	var body []byte
	contentType := "application/json"

	if e.signingKey != nil {
		token, err := SignSET(set, e.signingKey)
		if err != nil {
			return fmt.Errorf("sign SET: %w", err)
		}
		body = []byte(token)
		contentType = "application/secevent+jwt"
	} else {
		var err error
		body, err = json.Marshal(set)
		if err != nil {
			return fmt.Errorf("marshal SET: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, e.receiverURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST to receiver: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("receiver returned non-2xx status: %d", resp.StatusCode)
	}
	return nil
}
