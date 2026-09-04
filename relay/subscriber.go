package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

// Subscriber connects to the trust receiver, creates a stream subscription for
// the event types declared in the sinks config, and opens an SSE connection to
// receive inbound SETs. Each validated SET is forwarded to the Router.
type Subscriber struct {
	ReceiverURL string
	Router      *Router
	log         hclog.Logger
	client      *http.Client
}

// NewSubscriber constructs a Subscriber. receiverURL is the trust receiver base URL
// (e.g. "http://ssf-trust-receiver:9090").
func NewSubscriber(receiverURL string, router *Router, log hclog.Logger) *Subscriber {
	return &Subscriber{
		ReceiverURL: strings.TrimRight(receiverURL, "/"),
		Router:      router,
		log:         log.Named("subscriber"),
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

// streamCreateReq is the POST /v1/streams request body.
type streamCreateReq struct {
	TransmitterURL   string   `json:"transmitter_url"`
	EventTypes       []string `json:"event_types"`
	EnrollmentPolicy string   `json:"enrollment_policy"`
}

// streamCreateResp is the minimal subset of the POST /v1/streams response we need.
type streamCreateResp struct {
	ID string `json:"id"`
}

// Run blocks until ctx is cancelled, reconnecting on any SSE disconnect with
// exponential back-off (cap 60s). It creates (or re-creates) a stream
// subscription on each connect attempt.
func (s *Subscriber) Run(ctx context.Context) error {
	eventTypes := s.Router.EventTypes()
	if len(eventTypes) == 0 {
		s.log.Warn("no sinks configured — subscriber idle")
		<-ctx.Done()
		return nil
	}

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		streamID, err := s.createStream(ctx, eventTypes)
		if err != nil {
			s.log.Error("failed to create stream subscription", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
				backoff = capDuration(backoff*2, maxBackoff)
				continue
			}
		}
		backoff = 2 * time.Second // reset on successful connect

		s.log.Info("stream subscription created", "stream_id", streamID, "event_types", eventTypes)

		if err := s.readSSE(ctx, streamID); err != nil {
			s.log.Warn("SSE connection lost", "err", err, "stream_id", streamID, "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
			backoff = capDuration(backoff*2, maxBackoff)
		}
	}
}

// createStream POSTs to /v1/streams to register a subscription and returns the stream ID.
func (s *Subscriber) createStream(ctx context.Context, eventTypes []string) (string, error) {
	body, _ := json.Marshal(streamCreateReq{
		TransmitterURL:   s.ReceiverURL,
		EventTypes:       eventTypes,
		EnrollmentPolicy: "implicit",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.ReceiverURL+"/v1/streams", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /v1/streams: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST /v1/streams: HTTP %d", resp.StatusCode)
	}

	var sr streamCreateResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return "", fmt.Errorf("decode stream response: %w", err)
	}
	if sr.ID == "" {
		return "", fmt.Errorf("stream response missing id")
	}
	return sr.ID, nil
}

// readSSE opens GET /v1/streams/{id}/events and feeds data lines to the Router
// until the connection closes or ctx is cancelled.
func (s *Subscriber) readSSE(ctx context.Context, streamID string) error {
	url := fmt.Sprintf("%s/v1/streams/%s/events", s.ReceiverURL, streamID)

	// No Timeout on the SSE client — it's a long-lived connection.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	sseClient := &http.Client{} // no timeout — SSE is streaming
	resp, err := sseClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}

	s.log.Info("SSE connected", "stream_id", streamID)

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20))
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil
		}

		line := scanner.Text()

		// SSE comments (keepalive) — ignore.
		if strings.HasPrefix(line, ":") || line == "" {
			continue
		}

		// SSE data lines: "data: <json>"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		payload := strings.TrimPrefix(line, "data: ")

		var set InboundSET
		if err := json.Unmarshal([]byte(payload), &set); err != nil {
			s.log.Warn("failed to decode inbound SET", "err", err, "raw", payload)
			continue
		}

		s.log.Info("inbound SET received", "event_type", set.EventType, "source_id", set.SourceID)

		if err := s.Router.Handle(ctx, set); err != nil {
			s.log.Error("router error handling inbound SET", "err", err, "event_type", set.EventType)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("SSE read error: %w", err)
	}
	return fmt.Errorf("SSE stream closed")
}

func capDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
