package relay

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	// socketScanBuf is the per-connection scanner buffer. Vault audit entries
	// can be large (full request + response JSON), so we use 1 MiB.
	socketScanBuf = 1 << 20
)

// ListenSocket listens on addr for incoming connections, reads audit entries
// line-by-line, parses them with src, and calls emit for each resulting Event.
//
// addr may be a Unix socket path (e.g. /tmp/vault-audit.sock) or a TCP address
// prefixed with "tcp://" (e.g. tcp://127.0.0.1:9090).
//
// Unlike Tail, ListenSocket enables backpressure: a slow relay causes the
// socket buffer to fill, and the sender (Vault) blocks rather than losing events.
// Log rotation and file truncation are not concerns because there is no file.
//
// ListenSocket returns nil when ctx is cancelled.
func ListenSocket(ctx context.Context, log Logger, addr string, src Source, emit func(Event)) error {
	network, address := parseSocketAddr(addr)

	// Remove stale Unix socket file so Listen does not return "address already in use".
	if network == "unix" {
		_ = os.Remove(address)
	}

	ln, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("socket listen %q: %w", addr, err)
	}

	// Close the listener when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	log.Infof("socket listener ready addr=%s", addr)

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil // normal shutdown
			}
			log.Warnf("socket accept error: %v — continuing", err)
			continue
		}
		log.Infof("socket connection accepted remote=%s", conn.RemoteAddr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleSocketConn(ctx, log, conn, src, emit)
		}()
	}
}

// handleSocketConn reads newline-delimited JSON from conn until the connection
// closes or ctx is cancelled, parsing each line with src.
func handleSocketConn(ctx context.Context, log Logger, conn net.Conn, src Source, emit func(Event)) {
	defer conn.Close()

	// Close conn when ctx is cancelled so the scanner unblocks.
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	defer close(stop)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, socketScanBuf), socketScanBuf)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if event, ok := src.Parse(line); ok {
			emit(event)
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		log.Warnf("socket read error remote=%s: %v", conn.RemoteAddr(), err)
	}
}

// parseSocketAddr returns the network type and address for net.Listen.
// A "tcp://" prefix selects TCP; anything else is treated as a Unix socket path.
func parseSocketAddr(addr string) (network, address string) {
	if strings.HasPrefix(addr, "tcp://") {
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	}
	return "unix", addr
}
