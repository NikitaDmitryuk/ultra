// Package rtcsupervisor owns disposable transport processes, without relay credentials.
package rtcsupervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

type Session struct {
	Generation string `json:"generation"`
	Provider   string `json:"provider"`
	Room       string `json:"room"`
	Key        string `json:"key"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}
type Status struct {
	Generation string     `json:"generation"`
	Running    bool       `json:"running"`
	Ready      bool       `json:"ready"`
	Error      string     `json:"error"`
	Checked    *time.Time `json:"checked"`
}
type Client struct{ Socket string }

func (c Client) Sync(ctx context.Context, sessions []Session) ([]Status, error) {
	b, e := json.Marshal(sessions)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, e := http.NewRequestWithContext(ctx, "PUT", "http://local/sessions", bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("supervisor unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return nil, errors.New("supervisor unavailable")
	}
	var out []Status
	e = json.NewDecoder(resp.Body).Decode(&out)
	return out, e
}
