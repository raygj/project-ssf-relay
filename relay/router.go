package relay

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
)

// Router dispatches inbound SETs to registered ActionAdapters by event type URI.
// Multiple adapters may handle the same event type — all are called in order.
type Router struct {
	adapters map[string][]ActionAdapter // event type URI → adapters (fan-out)
	log      hclog.Logger
}

// NewRouter returns an empty Router. Register adapters before calling Handle.
func NewRouter(log hclog.Logger) *Router {
	return &Router{
		adapters: make(map[string][]ActionAdapter),
		log:      log.Named("router"),
	}
}

// Register adds an adapter. Each event type the adapter declares is appended to
// the handler list for that type, enabling fan-out to multiple adapters.
func (r *Router) Register(a ActionAdapter) {
	for _, et := range a.EventTypes() {
		r.adapters[et] = append(r.adapters[et], a)
	}
	r.log.Info("registered action adapter", "name", a.Name(), "event_types", a.EventTypes())
}

// Handle routes the inbound SET to all matching adapters in registration order.
// All adapters are called even if one errors; all errors are returned combined.
func (r *Router) Handle(ctx context.Context, set InboundSET) error {
	adapters := r.adapters[set.EventType]
	if len(adapters) == 0 {
		r.log.Debug("no adapter for event type — dropping", "event_type", set.EventType)
		return nil
	}
	var errs []string
	for _, a := range adapters {
		if err := a.Act(ctx, set); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", a.Name(), err))
			continue
		}
		r.log.Info("action complete", "adapter", a.Name(), "event_type", set.EventType, "source_id", set.SourceID)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", fmt.Sprintf("%v", errs))
	}
	return nil
}

// EventTypes returns all event type URIs that have a registered adapter.
func (r *Router) EventTypes() []string {
	out := make([]string, 0, len(r.adapters))
	for et := range r.adapters {
		out = append(out, et)
	}
	return out
}
