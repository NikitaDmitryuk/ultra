package mimic

import (
	"fmt"
	"strings"
)

var constructors = map[string]func() (Strategy, error){}

// Register adds a named preset. Typically called from init() in preset files.
func Register(name string, ctor func() (Strategy, error)) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" || ctor == nil {
		panic("mimic: invalid Register")
	}
	constructors[key] = ctor
}

// New returns a strategy by preset name, or an error if unknown.
func New(preset string) (Strategy, error) {
	key := strings.ToLower(strings.TrimSpace(preset))
	if key == "" {
		key = "apijson"
	}
	ctor, ok := constructors[key]
	if !ok {
		return nil, fmt.Errorf("mimic: unknown preset %q", preset)
	}
	return ctor()
}
