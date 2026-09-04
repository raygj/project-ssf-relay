package actions

import (
	"fmt"
	"sync"

	"github.com/raygj/ssf-relay/relay"
)

// Factory constructs an ActionAdapter from a config map.
type Factory func(cfg map[string]interface{}) (relay.ActionAdapter, error)

var (
	mu       sync.Mutex
	registry = map[string]Factory{}
)

// Register adds a Factory under the given name. Panics on duplicate registration.
// Called from action package init() functions.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("ssf-relay: action %q already registered", name))
	}
	registry[name] = f
}

// Build looks up the Factory for name and calls it with cfg.
func Build(name string, cfg map[string]interface{}) (relay.ActionAdapter, error) {
	mu.Lock()
	f, ok := registry[name]
	mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown action type %q (did you blank-import it?)", name)
	}
	return f(cfg)
}
