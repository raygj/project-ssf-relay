package relay

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mockLogger satisfies the Logger interface for tests.
type mockLogger struct{}

func (m *mockLogger) Infof(msg string, args ...interface{})  {}
func (m *mockLogger) Warnf(msg string, args ...interface{})  {}
func (m *mockLogger) Errorf(msg string, args ...interface{}) {}

// mockSource parses lines as events using "TYPE:CORR" format.
type mockSource struct{ name string }

func (s *mockSource) Name() string { return s.name }
func (s *mockSource) Parse(line string) (Event, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return Event{}, false
	}
	return Event{
		Type:          parts[0],
		CorrelationID: parts[1],
	}, true
}

func TestTail_ProcessesLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	log := &mockLogger{}
	src := &mockSource{name: "test"}

	var events []Event
	done := make(chan struct{})

	go func() {
		defer close(done)
		Tail(ctx, log, path, src, func(e Event) {
			events = append(events, e)
		})
	}()

	// Give the tailer time to start and seek to end.
	time.Sleep(100 * time.Millisecond)

	// Write lines to the file.
	f.WriteString("event-a:corr-1\n")
	f.WriteString("event-b:corr-2\n")
	f.WriteString("event-c:corr-3\n")
	f.Close()

	// Wait for events to be processed.
	time.Sleep(700 * time.Millisecond)
	cancel()
	<-done

	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].Type != "event-a" || events[0].CorrelationID != "corr-1" {
		t.Errorf("unexpected event[0]: %+v", events[0])
	}
	if events[1].Type != "event-b" {
		t.Errorf("unexpected event[1]: %+v", events[1])
	}
	if events[2].Type != "event-c" {
		t.Errorf("unexpected event[2]: %+v", events[2])
	}
}

func TestTail_SkipsUnparseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	log := &mockLogger{}
	src := &mockSource{name: "test"}

	var events []Event
	done := make(chan struct{})

	go func() {
		defer close(done)
		Tail(ctx, log, path, src, func(e Event) {
			events = append(events, e)
		})
	}()

	time.Sleep(100 * time.Millisecond)

	// One valid, one invalid (no colon).
	f.WriteString("not-valid-no-colon\n")
	f.WriteString("valid-type:corr-999\n")
	f.Close()

	time.Sleep(700 * time.Millisecond)
	cancel()
	<-done

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(events), events)
	}
	if events[0].Type != "valid-type" {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

func TestTail_TruncationDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Write initial content so tailer advances its position.
	f.WriteString("event-a:before-truncation\n")
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	log := &mockLogger{}
	src := &mockSource{name: "test"}

	var events []Event
	done := make(chan struct{})

	go func() {
		defer close(done)
		Tail(ctx, log, path, src, func(e Event) {
			events = append(events, e)
		})
	}()

	// Let the tailer see and consume the first line.
	time.Sleep(800 * time.Millisecond)

	// Truncate the file by overwriting with a new file.
	f2, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f2.WriteString("event-b:after-truncation\n")
	f2.Close()

	time.Sleep(800 * time.Millisecond)
	cancel()
	<-done

	// event-a was written before the seek-to-end, so it won't be seen.
	// event-b should appear after truncation recovery.
	found := false
	for _, e := range events {
		if e.CorrelationID == "after-truncation" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find event after truncation; got events: %+v", events)
	}
}

func TestTail_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	if _, err := os.Create(path); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	log := &mockLogger{}
	src := &mockSource{name: "test"}

	err := Tail(ctx, log, path, src, func(e Event) {})
	if err != nil {
		t.Errorf("expected nil error on context cancel, got: %v", err)
	}
}
