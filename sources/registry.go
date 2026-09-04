package sources

import (
	"fmt"
	"sync"

	"github.com/raygj/ssf-relay/relay"
)

// Factory is a function that constructs a relay.Source from a config map.
type Factory func(cfg map[string]interface{}) (relay.Source, error)

var (
	mu       sync.Mutex
	registry = map[string]Factory{}
)

// Register adds a Factory under the given name. Panics on duplicate registration.
// Intended to be called from source package init() functions.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("ssf-relay: source %q already registered", name))
	}
	registry[name] = f
}

// Build looks up the Factory for name and calls it with cfg.
func Build(name string, cfg map[string]interface{}) (relay.Source, error) {
	mu.Lock()
	f, ok := registry[name]
	mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown source type %q (did you blank-import it?)", name)
	}
	return f(cfg)
}
