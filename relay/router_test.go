package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

const (
	eventDegraded  = "https://schemas.openid.net/secevent/caep/event-type/source-degraded"
	eventRecovered = "https://schemas.openid.net/secevent/caep/event-type/source-recovered"
)

type stubAdapter struct {
	name     string
	types    []string
	actCalls int
	actErr   error
	lastSet  InboundSET
}

func (a *stubAdapter) Name() string { return a.name }

func (a *stubAdapter) EventTypes() []string { return a.types }

func (a *stubAdapter) Act(_ context.Context, set InboundSET) error {
	a.actCalls++
	a.lastSet = set
	return a.actErr
}

func TestRouter_HandleFanOut(t *testing.T) {
	r := NewRouter(hclog.NewNullLogger())
	vault := &stubAdapter{name: "vault", types: []string{eventCompromised}}
	webhook := &stubAdapter{name: "webhook", types: []string{eventCompromised}}
	r.Register(vault)
	r.Register(webhook)

	set := InboundSET{EventType: eventCompromised, SourceID: "src-1"}
	if err := r.Handle(context.Background(), set); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if vault.actCalls != 1 || webhook.actCalls != 1 {
		t.Errorf("fan-out: vault=%d webhook=%d", vault.actCalls, webhook.actCalls)
	}
}

func TestRouter_HandlePartialError(t *testing.T) {
	r := NewRouter(hclog.NewNullLogger())
	ok := &stubAdapter{name: "ok", types: []string{eventCompromised}}
	fail := &stubAdapter{name: "fail", types: []string{eventCompromised}, actErr: errors.New("boom")}
	r.Register(ok)
	r.Register(fail)

	err := r.Handle(context.Background(), InboundSET{EventType: eventCompromised})
	if err == nil {
		t.Fatal("expected combined error")
	}
	if ok.actCalls != 1 {
		t.Errorf("ok adapter should still run, calls=%d", ok.actCalls)
	}
	if !strings.Contains(err.Error(), "fail") {
		t.Errorf("error should mention failing adapter: %v", err)
	}
}

func TestRouter_HandleUnknownEventType(t *testing.T) {
	r := NewRouter(hclog.NewNullLogger())
	r.Register(&stubAdapter{name: "vault", types: []string{eventCompromised}})

	if err := r.Handle(context.Background(), InboundSET{EventType: eventDegraded}); err != nil {
		t.Fatalf("unknown event type should be no-op: %v", err)
	}
}

func TestRouter_EventTypes(t *testing.T) {
	r := NewRouter(hclog.NewNullLogger())
	r.Register(&stubAdapter{name: "vault", types: []string{eventCompromised, eventDegraded}})
	r.Register(&stubAdapter{name: "webhook", types: []string{eventRecovered}})

	types := r.EventTypes()
	if len(types) != 3 {
		t.Fatalf("EventTypes len: want 3 got %d (%v)", len(types), types)
	}
	seen := map[string]bool{}
	for _, et := range types {
		seen[et] = true
	}
	for _, want := range []string{eventCompromised, eventDegraded, eventRecovered} {
		if !seen[want] {
			t.Errorf("missing event type %q in %v", want, types)
		}
	}
}
