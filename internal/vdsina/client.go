// Package vdsina implements a small, conservative client for the VDSina user API.
package vdsina

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL  = "https://userapi.vdsina.ru"
	maxResponseSize = 4 << 20
)

// Client performs authenticated requests to the VDSina user API.
type Client struct {
	token   string
	baseURL string
	http    *http.Client
}

// Resource retains provider-specific fields while exposing common identifiers.
type Resource struct {
	ID   json.RawMessage `json:"id"`
	Name string          `json:"name"`
	Raw  json.RawMessage `json:"-"`
}

// CreateServerRequest contains the identifiers required to provision a server.
type CreateServerRequest struct {
	DatacenterID int64  `json:"datacenter"`
	ServerPlanID int64  `json:"server-plan"`
	TemplateID   int64  `json:"template"`
	SSHKeyID     int64  `json:"ssh-key"`
	Name         string `json:"name"`
}

// New creates a client using VDSina's public API endpoint and a bounded timeout.
func New(token string) *Client {
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{token: token, baseURL: defaultBaseURL, http: httpClient}
}

// AccountLimit reads the account limits.
func (c *Client) AccountLimit(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/v1/account.limit")
}

// Servers lists servers.
func (c *Client) Servers(ctx context.Context) ([]Resource, error) {
	return c.getList(ctx, "/v1/server")
}

// Server retrieves one server by ID.
func (c *Client) Server(ctx context.Context, id int64) (Resource, error) {
	if id <= 0 {
		return Resource{}, errors.New("vdsina: server ID must be positive")
	}
	return c.getResource(ctx, "/v1/server/"+strconv.FormatInt(id, 10))
}

// ServerGroups lists server groups.
func (c *Client) ServerGroups(ctx context.Context) ([]Resource, error) {
	return c.getList(ctx, "/v1/server-group")
}

// Datacenters lists datacenters.
func (c *Client) Datacenters(ctx context.Context) ([]Resource, error) {
	return c.getList(ctx, "/v1/datacenter")
}

// Templates lists server templates.
func (c *Client) Templates(ctx context.Context) ([]Resource, error) {
	return c.getList(ctx, "/v1/template")
}

// ServerPlans lists plans available for a server group.
func (c *Client) ServerPlans(ctx context.Context, groupID int64) ([]Resource, error) {
	if groupID <= 0 {
		return nil, errors.New("vdsina: server group ID must be positive")
	}
	return c.getList(ctx, "/v1/server-plan/"+strconv.FormatInt(groupID, 10))
}

// CreateServer sends one provisioning request. It never retries: a transport or
// decoding error may leave the provider-side outcome unknown.
func (c *Client) CreateServer(ctx context.Context, input CreateServerRequest) (Resource, error) {
	if input.DatacenterID <= 0 || input.ServerPlanID <= 0 || input.TemplateID <= 0 || input.SSHKeyID <= 0 {
		return Resource{}, errors.New("vdsina: datacenter, server plan, template, and SSH key IDs must be positive")
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return Resource{}, errors.New("vdsina: server name is required")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return Resource{}, errors.New("vdsina: could not encode server request")
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/server", body)
	if err != nil {
		return Resource{}, err
	}
	var result Resource
	if err := json.Unmarshal(data, &result); err != nil {
		return Resource{}, errors.New("vdsina: invalid server response")
	}
	if len(result.ID) == 0 || string(result.ID) == "null" {
		return Resource{}, errors.New("vdsina: server response is missing ID")
	}
	result.Raw = append(result.Raw[:0], data...)
	return result, nil
}

func (c *Client) getRaw(ctx context.Context, path string) (json.RawMessage, error) {
	return c.request(ctx, http.MethodGet, path, nil)
}

func (c *Client) getList(ctx context.Context, path string) ([]Resource, error) {
	data, err := c.getRaw(ctx, path)
	if err != nil {
		return nil, err
	}
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, errors.New("vdsina: invalid list response")
	}
	result := make([]Resource, 0, len(values))
	for _, value := range values {
		var item Resource
		if err := json.Unmarshal(value, &item); err != nil {
			return nil, errors.New("vdsina: invalid list response")
		}
		item.Raw = append(item.Raw[:0], value...)
		result = append(result, item)
	}
	return result, nil
}

func (c *Client) getResource(ctx context.Context, path string) (Resource, error) {
	data, err := c.getRaw(ctx, path)
	if err != nil {
		return Resource{}, err
	}
	var item Resource
	if err := json.Unmarshal(data, &item); err != nil {
		return Resource{}, errors.New("vdsina: invalid resource response")
	}
	item.Raw = append(item.Raw[:0], data...)
	return item, nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) (json.RawMessage, error) {
	if c == nil || c.http == nil {
		return nil, errors.New("vdsina: client is not configured")
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, errors.New("vdsina: invalid API endpoint")
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base.String(), reader)
	if err != nil {
		return nil, errors.New("vdsina: could not create request")
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("vdsina: request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, errors.New("vdsina: could not read response")
	}
	if len(data) > maxResponseSize {
		return nil, errors.New("vdsina: response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vdsina: API returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, errors.New("vdsina: invalid API response")
	}
	if envelope.Status != "ok" {
		return nil, errors.New("vdsina: API request was not successful")
	}
	if len(envelope.Data) == 0 {
		return nil, errors.New("vdsina: API response is missing data")
	}
	return envelope.Data, nil
}
