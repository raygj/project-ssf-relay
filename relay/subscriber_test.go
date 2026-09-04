package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
)

const eventCompromised = "https://schemas.openid.net/secevent/caep/event-type/source-compromised"

type recordingAdapter struct {
	name  string
	types []string
	mu    sync.Mutex
	sets  []InboundSET
	err   error
}

func (a *recordingAdapter) Name() string { return a.name }

func (a *recordingAdapter) EventTypes() []string { return a.types }

func (a *recordingAdapter) Act(_ context.Context, set InboundSET) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sets = append(a.sets, set)
	return a.err
}

func (a *recordingAdapter) last() (InboundSET, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sets) == 0 {
		return InboundSET{}, false
	}
	return a.sets[len(a.sets)-1], true
}

func TestSubscriber_createStream(t *testing.T) {
	var gotBody streamCreateReq
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/streams", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"stream-test-1"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	router := NewRouter(hclog.NewNullLogger())
	router.Register(&recordingAdapter{
		name:  "vault",
		types: []string{eventCompromised},
	})

	sub := NewSubscriber(srv.URL, router, hclog.NewNullLogger())
	id, err := sub.createStream(context.Background(), router.EventTypes())
	if err != nil {
		t.Fatalf("createStream: %v", err)
	}
	if id != "stream-test-1" {
		t.Errorf("stream id: want stream-test-1 got %q", id)
	}
	if gotBody.EnrollmentPolicy != "implicit" {
		t.Errorf("enrollment_policy: want implicit got %q", gotBody.EnrollmentPolicy)
	}
	if len(gotBody.EventTypes) != 1 || gotBody.EventTypes[0] != eventCompromised {
		t.Errorf("event_types: got %v", gotBody.EventTypes)
	}
}

func TestSubscriber_SSEToRouter(t *testing.T) {
	setPayload := InboundSET{
		EventType:     eventCompromised,
		SourceID:      "demo-workload",
		CorrelationID: "corr-1",
		Reason:        "manual demo trigger",
	}
	data, err := json.Marshal(setPayload)
	if err != nil {
		t.Fatal(err)
	}

	var streamCreated atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/streams", func(w http.ResponseWriter, r *http.Request) {
		streamCreated.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"stream-test-1"}`)
	})
	mux.HandleFunc("GET /v1/streams/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer does not support flush")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		<-r.Context().Done()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	adapter := &recordingAdapter{
		name:  "vault",
		types: []string{eventCompromised},
	}
	router := NewRouter(hclog.NewNullLogger())
	router.Register(adapter)

	sub := NewSubscriber(srv.URL, router, hclog.NewNullLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- sub.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if got, ok := adapter.last(); ok {
			if got.EventType != setPayload.EventType {
				t.Errorf("event_type: want %q got %q", setPayload.EventType, got.EventType)
			}
			if got.SourceID != setPayload.SourceID {
				t.Errorf("source_id: want %q got %q", setPayload.SourceID, got.SourceID)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for inbound SET (stream_created=%v)", streamCreated.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSubscriber_createStream_nonCreated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sub := NewSubscriber(srv.URL, NewRouter(hclog.NewNullLogger()), hclog.NewNullLogger())
	_, err := sub.createStream(context.Background(), []string{eventCompromised})
	if err == nil {
		t.Fatal("expected error for non-201 response")
	}
}
