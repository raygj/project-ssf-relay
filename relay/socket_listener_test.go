package relay

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tempSockPath returns a Unix socket path short enough for macOS (sun_path ≤ 103 bytes).
// t.TempDir() paths exceed this limit when the test name is long.
func tempSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// waitForSocket polls until the Unix socket file exists or the deadline passes.
func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", path)
}

// sendLines connects to addr and writes lines, then closes the connection.
func sendLines(t *testing.T, network, addr string, lines []string) {
	t.Helper()
	conn, err := net.Dial(network, addr)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, addr, err)
	}
	defer conn.Close()
	for _, l := range lines {
		fmt.Fprintln(conn, l)
	}
}

// waitForEvents waits up to timeout for n events and returns them.
func waitForEvents(ch <-chan Event, n int, timeout time.Duration) []Event {
	var got []Event
	deadline := time.After(timeout)
	for len(got) < n {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestListenSocket_Unix_ParsesLines(t *testing.T) {
	sockPath := tempSockPath(t)

	src := &mockSource{name: "vault"}
	events := make(chan Event, 10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ListenSocket(ctx, &mockLogger{}, sockPath, src, func(e Event) { events <- e }) //nolint:errcheck
	}()
	waitForSocket(t, sockPath, 2*time.Second)

	sendLines(t, "unix", sockPath, []string{"token-issued:corr-1", "secret-accessed:corr-2"})

	got := waitForEvents(events, 2, 2*time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	if got[0].Type != "token-issued" || got[0].CorrelationID != "corr-1" {
		t.Errorf("event[0]: %+v", got[0])
	}
	if got[1].Type != "secret-accessed" || got[1].CorrelationID != "corr-2" {
		t.Errorf("event[1]: %+v", got[1])
	}
}

func TestListenSocket_TCP_ParsesLines(t *testing.T) {
	src := &mockSource{name: "vault"}
	events := make(chan Event, 10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Find a free TCP port before starting the listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	boundAddr := ln.Addr().String()
	ln.Close()

	ready := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(ready)
		ListenSocket(ctx, &mockLogger{}, "tcp://"+boundAddr, src, func(e Event) { events <- e }) //nolint:errcheck
	}()
	<-ready

	sendLines(t, "tcp", boundAddr, []string{"preflight-denied:corr-3"})

	got := waitForEvents(events, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Type != "preflight-denied" {
		t.Errorf("unexpected type: %q", got[0].Type)
	}
}

func TestListenSocket_MultipleConnections(t *testing.T) {
	sockPath := tempSockPath(t)

	src := &mockSource{name: "vault"}
	events := make(chan Event, 20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ListenSocket(ctx, &mockLogger{}, sockPath, src, func(e Event) { events <- e }) //nolint:errcheck
	}()
	waitForSocket(t, sockPath, 2*time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sendLines(t, "unix", sockPath, []string{fmt.Sprintf("token-issued:corr-%d", i)})
		}(i)
	}
	wg.Wait()

	got := waitForEvents(events, 5, 3*time.Second)
	if len(got) != 5 {
		t.Fatalf("expected 5 events from 5 connections, got %d", len(got))
	}
}

func TestListenSocket_ContextCancel_Stops(t *testing.T) {
	sockPath := tempSockPath(t)

	src := &mockSource{name: "vault"}
	done := make(chan error, 1)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		err := ListenSocket(ctx, &mockLogger{}, sockPath, src, func(_ Event) {})
		done <- err
	}()
	waitForSocket(t, sockPath, 2*time.Second)

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenSocket did not return after context cancel")
	}
}

func TestListenSocket_StaleSocketFile_Removed(t *testing.T) {
	sockPath := tempSockPath(t)

	// Create a stale socket file.
	if err := os.WriteFile(sockPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	src := &mockSource{name: "vault"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan error, 1)
	go func() {
		err := ListenSocket(ctx, &mockLogger{}, sockPath, src, func(_ Event) {})
		started <- err
	}()
	// Wait for socket to appear — confirms stale file was removed and Listen succeeded.
	waitForSocket(t, sockPath, 2*time.Second)
	cancel()

	select {
	case err := <-started:
		if err != nil {
			t.Errorf("stale socket should have been cleaned up, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("ListenSocket did not return after context cancel")
	}
}

func TestListenSocket_LargeLine(t *testing.T) {
	sockPath := tempSockPath(t)

	src := &mockSource{name: "vault"}
	events := make(chan Event, 5)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ListenSocket(ctx, &mockLogger{}, sockPath, src, func(e Event) { events <- e }) //nolint:errcheck
	}()
	waitForSocket(t, sockPath, 2*time.Second)

	// Build a line just under 1MB: "TYPE:CORR<padding>"
	// mockSource.Parse splits on ":" so we embed padding in the correlation ID.
	padding := strings.Repeat("x", 900*1024)
	bigLine := "token-issued:corr-big-" + padding

	sendLines(t, "unix", sockPath, []string{bigLine})

	got := waitForEvents(events, 1, 2*time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 event for large line, got %d", len(got))
	}
	if got[0].Type != "token-issued" {
		t.Errorf("unexpected type: %q", got[0].Type)
	}
}

func TestParseSocketAddr(t *testing.T) {
	cases := []struct{ addr, wantNet, wantAddr string }{
		{"/tmp/vault.sock", "unix", "/tmp/vault.sock"},
		{"tcp://127.0.0.1:9090", "tcp", "127.0.0.1:9090"},
		{"tcp://[::1]:9090", "tcp", "[::1]:9090"},
	}
	for _, c := range cases {
		n, a := parseSocketAddr(c.addr)
		if n != c.wantNet || a != c.wantAddr {
			t.Errorf("parseSocketAddr(%q) = (%q,%q) want (%q,%q)", c.addr, n, a, c.wantNet, c.wantAddr)
		}
	}
}
