package relay

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"
)

// Logger is a minimal structured logger interface compatible with hclog.Logger.
type Logger interface {
	Infof(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
}

const (
	tailBufSize   = 4096
	retryBackoff  = 5 * time.Second
	rotationCheck = 500 * time.Millisecond
)

// Tail opens the file at path, seeks to EOF, and then delivers parsed Events
// to emit as new lines arrive. It handles log rotation (rename + reopen) and
// truncation. Returns nil when ctx is cancelled.
func Tail(ctx context.Context, log Logger, path string, src Source, emit func(Event)) error {
	f, err := openWithRetry(ctx, log, path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Seek to end so we don't replay history on startup.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	var pending []byte
	buf := make([]byte, tailBufSize)
	ticker := time.NewTicker(rotationCheck)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// Rotation detection: check if the current inode differs from path.
		if rotated, err := isRotated(f, path); err == nil && rotated {
			log.Infof("log rotation detected for %s, reopening", path)
			f.Close()
			f, err = openWithRetry(ctx, log, path)
			if err != nil {
				return err
			}
			pending = nil
			continue
		}

		// Truncation detection: if our position is beyond EOF, seek to start.
		pos, _ := f.Seek(0, io.SeekCurrent)
		fi, err := f.Stat()
		if err == nil && pos > fi.Size() {
			log.Infof("truncation detected for %s, seeking to beginning", path)
			f.Seek(0, io.SeekStart)
			pending = nil
			continue
		}

		// Read available bytes.
		n, err := f.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			for {
				idx := bytes.IndexByte(pending, '\n')
				if idx < 0 {
					break
				}
				line := string(pending[:idx])
				pending = pending[idx+1:]
				if line == "" {
					continue
				}
				if event, ok := src.Parse(line); ok {
					emit(event)
				}
			}
		}
		if err != nil && err != io.EOF {
			log.Errorf("read error on %s: %v", path, err)
		}
	}
}

// openWithRetry tries to open path, retrying every retryBackoff until success
// or ctx is cancelled.
func openWithRetry(ctx context.Context, log Logger, path string) (*os.File, error) {
	for {
		f, err := os.Open(path)
		if err == nil {
			return f, nil
		}
		log.Warnf("cannot open %s: %v — retrying in %s", path, err, retryBackoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryBackoff):
		}
	}
}

// isRotated returns true if the file at path has a different inode than f.
func isRotated(f *os.File, path string) (bool, error) {
	fi1, err := f.Stat()
	if err != nil {
		return false, err
	}
	fi2, err := os.Stat(path)
	if err != nil {
		// If path no longer exists, rotation is in progress.
		return true, nil
	}
	return !os.SameFile(fi1, fi2), nil
}
