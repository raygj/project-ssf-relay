package relay

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/raygj/ssf-relay/config"
)

// SourceBuilder is a function that builds a Source from a config map.
// It mirrors sources.Factory but lives here to avoid a circular import.
type SourceBuilder func(name string, cfg map[string]interface{}) (Source, error)

// Manager orchestrates one goroutine per configured source.
type Manager struct {
	cfg     config.Config
	log     hclog.Logger
	emitter *Emitter
	build   SourceBuilder
}

// NewManager creates a Manager. build is provided by main to avoid importing
// the sources package from relay (dependency inversion).
func NewManager(cfg config.Config, log hclog.Logger, emitter *Emitter, build SourceBuilder) *Manager {
	return &Manager{
		cfg:     cfg,
		log:     log,
		emitter: emitter,
		build:   build,
	}
}

// Run starts one goroutine per source in cfg.Sources and waits for all to finish.
// It returns when ctx is cancelled or all goroutines have exited.
func (m *Manager) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errs := make(chan error, len(m.cfg.Sources))

	for _, sc := range m.cfg.Sources {
		sc := sc // capture
		src, err := m.build(sc.Type, sc.Config)
		if err != nil {
			return fmt.Errorf("build source %q (type %q): %w", sc.Name, sc.Type, err)
		}

		transport := sc.Transport
		if transport == "" {
			transport = "file"
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			log := m.log.Named(sc.Name)
			adapted := &hclogAdapter{log}
			onEvent := func(event Event) {
				if err := m.emitter.Emit(sc.Name, event); err != nil {
					log.Error("emit failed", "error", err)
				}
			}
			var runErr error
			switch transport {
			case "socket":
				runErr = ListenSocket(ctx, adapted, sc.Path, src, onEvent)
			default:
				runErr = Tail(ctx, adapted, sc.Path, src, onEvent)
			}
			if runErr != nil {
				errs <- fmt.Errorf("source %q: %w", sc.Name, runErr)
			}
		}()
	}

	wg.Wait()
	close(errs)

	// Return the first error, if any.
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// hclogAdapter adapts hclog.Logger to relay.Logger.
type hclogAdapter struct {
	l hclog.Logger
}

func (a *hclogAdapter) Infof(msg string, args ...interface{}) {
	a.l.Info(fmt.Sprintf(msg, args...))
}
func (a *hclogAdapter) Warnf(msg string, args ...interface{}) {
	a.l.Warn(fmt.Sprintf(msg, args...))
}
func (a *hclogAdapter) Errorf(msg string, args ...interface{}) {
	a.l.Error(fmt.Sprintf(msg, args...))
}
