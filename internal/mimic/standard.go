package mimic

// Standard uses only the host/path supplied by the tunnel specification. It
// deliberately adds no application-specific browser, gaming or API headers.
type Standard struct{}

func init()                                      { Register("standard", func() (Strategy, error) { return Standard{}, nil }) }
func (Standard) Name() string                    { return "standard" }
func (Standard) Host() string                    { return "splithttp.invalid" }
func (Standard) NextPath() string                { return "/ultra-xhttp" }
func (Standard) ExtraHeaders() map[string]string { return nil }
