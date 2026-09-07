// Package cloud manages explicitly confirmed Vultr provisioning operations.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("cloud service unavailable")
var ErrUnknownCreation = errors.New("creation outcome unknown; reconcile before retry")
var ErrPriceChanged = errors.New("offer expired or price changed")

type Region struct {
	ID      string `json:"id"`
	City    string `json:"city"`
	Country string `json:"country"`
}
type Cost struct {
	Monthly float64 `json:"monthly_cost"`
	Hourly  float64 `json:"hourly_cost"`
}
type Plan struct {
	ID        string `json:"id"`
	RAM       int    `json:"ram"`
	CPU       int    `json:"vcpu_count"`
	Disk      int    `json:"disk"`
	Bandwidth int    `json:"bandwidth"`
	Cost
	Locations    []string        `json:"locations"`
	LocationCost map[string]Cost `json:"location_cost"`
}

func (p Plan) Price(region string) Cost {
	if c, ok := p.LocationCost[region]; ok {
		return c
	}
	return p.Cost
}

type Instance struct {
	AllowedBandwidth int64    `json:"allowed_bandwidth"`
	ID               string   `json:"id"`
	Region           string   `json:"region"`
	Plan             string   `json:"plan"`
	IP               string   `json:"main_ip"`
	Status           string   `json:"status"`
	PowerStatus      string   `json:"power_status"`
	ServerStatus     string   `json:"server_status"`
	Tags             []string `json:"tags"`
}
type CreateRequest struct {
	Region   string   `json:"region"`
	Plan     string   `json:"plan"`
	OSID     int      `json:"os_id"`
	Label    string   `json:"label"`
	Tags     []string `json:"tags"`
	SSHKeys  []string `json:"sshkey_id"`
	Firewall string   `json:"firewall_group_id"`
	Backups  string   `json:"backups"`
	IPv6     bool     `json:"enable_ipv6"`
	DDoS     bool     `json:"ddos_protection"`
}
type APIError struct {
	Status int
	Code   string
}

func (e APIError) Error() string { return fmt.Sprintf("Vultr HTTP %d", e.Status) }

type Vultr struct {
	BaseURL string
	Key     string
	HTTP    *http.Client
}

func NewVultr(key string) *Vultr {
	return &Vultr{BaseURL: "https://api.vultr.com/v2", Key: key, HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (v *Vultr) requestOnce(ctx context.Context, method, path string, input, output any) error {
	body, e := json.Marshal(input)
	if e != nil {
		return ErrUnavailable
	}
	req, e := http.NewRequestWithContext(ctx, method, v.BaseURL+path, bytes.NewReader(body))
	if e != nil {
		return ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+v.Key)
	req.Header.Set("Content-Type", "application/json")
	response, e := v.HTTP.Do(req)
	if e != nil {
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			return APIError{Code: "provider_timeout"}
		}
		return APIError{Code: "provider_unreachable"}
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode/100 != 2 {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&body)
		return APIError{Status: response.StatusCode, Code: providerCode(response.StatusCode, body.Error)}
	}
	if output != nil && response.StatusCode != 204 {
		if json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output) != nil {
			return ErrUnavailable
		}
	}
	return nil
}
func list[T any](ctx context.Context, v *Vultr, path, field string) ([]T, error) {
	out := []T{}
	cursor := ""
	seen := map[string]bool{}
	for {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		query := path + separator + "per_page=500"
		if cursor != "" {
			query += "&cursor=" + url.QueryEscape(cursor)
		}
		var response map[string]json.RawMessage
		if e := v.request(ctx, "GET", query, nil, &response); e != nil {
			return nil, e
		}
		var page []T
		if json.Unmarshal(response[field], &page) != nil {
			return nil, ErrUnavailable
		}
		out = append(out, page...)
		var meta struct {
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if json.Unmarshal(response["meta"], &meta) != nil {
			return nil, ErrUnavailable
		}
		cursor = meta.Links.Next
		if cursor == "" {
			return out, nil
		}
		if seen[cursor] {
			return nil, ErrUnavailable
		}
		seen[cursor] = true
	}
}
func (v *Vultr) Regions(ctx context.Context) ([]Region, error) {
	return list[Region](ctx, v, "/regions", "regions")
}
func (v *Vultr) Plans(ctx context.Context) ([]Plan, error) {
	return list[Plan](ctx, v, "/plans?type=vc2", "plans")
}
func (v *Vultr) Instances(ctx context.Context) ([]Instance, error) {
	return list[Instance](ctx, v, "/instances", "instances")
}
func (v *Vultr) Available(ctx context.Context, region, plan string) (bool, error) {
	var response struct {
		Plans []string `json:"available_plans"`
	}
	e := v.request(ctx, "GET", "/regions/"+url.PathEscape(region)+"/availability?type=vc2", nil, &response)
	for _, p := range response.Plans {
		if p == plan {
			return true, e
		}
	}
	return false, e
}
func (v *Vultr) Create(ctx context.Context, input CreateRequest) (Instance, error) {
	var response struct {
		Instance Instance `json:"instance"`
	}
	e := v.request(ctx, "POST", "/instances", input, &response)
	if e != nil {
		var api APIError
		if errors.As(e, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 408 {
			return Instance{}, e
		}
		return Instance{}, errors.Join(ErrUnknownCreation, e)
	}
	if response.Instance.ID == "" {
		return Instance{}, ErrUnknownCreation
	}
	return response.Instance, nil
}
func (v *Vultr) Get(ctx context.Context, id string) (Instance, error) {
	var response struct {
		Instance Instance `json:"instance"`
	}
	e := v.request(ctx, "GET", "/instances/"+url.PathEscape(id), nil, &response)
	return response.Instance, e
}
func (v *Vultr) Delete(ctx context.Context, id string) error {
	e := v.request(ctx, "DELETE", "/instances/"+url.PathEscape(id), nil, nil)
	var api APIError
	if errors.As(e, &api) && api.Status == 404 {
		return nil
	}
	return e
}
func (v *Vultr) EnsureSSHKey(ctx context.Context, name, publicKey string) (string, error) {
	type key struct {
		ID  string `json:"id"`
		Key string `json:"ssh_key"`
	}
	keys, e := list[key](ctx, v, "/ssh-keys", "ssh_keys")
	if e != nil {
		return "", e
	}
	for _, k := range keys {
		if strings.TrimSpace(k.Key) == strings.TrimSpace(publicKey) {
			return k.ID, nil
		}
	}
	var response struct {
		Key key `json:"ssh_key"`
	}
	e = v.request(ctx, "POST", "/ssh-keys", map[string]string{"name": name, "ssh_key": publicKey}, &response)
	return response.Key.ID, e
}

func (v *Vultr) EnsureFirewall(ctx context.Context, operation, bridgeIP string, tunnelPort int) (string, error) {
	type group struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	name := "ultra-operation-" + operation
	groups, e := list[group](ctx, v, "/firewalls", "firewall_groups")
	if e != nil {
		return "", e
	}
	id := ""
	for _, g := range groups {
		if g.Description == name {
			if id != "" {
				return "", ErrConflict
			}
			id = g.ID
		}
	}
	if id == "" {
		var response struct {
			Group group `json:"firewall_group"`
		}
		if e = v.request(ctx, "POST", "/firewalls", map[string]string{"description": name}, &response); e != nil {
			return "", e
		}
		id = response.Group.ID
	}
	type rule struct {
		IPType   string `json:"ip_type"`
		Protocol string `json:"protocol"`
		Subnet   string `json:"subnet"`
		Size     int    `json:"subnet_size"`
		Port     string `json:"port"`
	}
	rules, e := list[rule](ctx, v, "/firewalls/"+url.PathEscape(id)+"/rules", "firewall_rules")
	if e != nil {
		return "", e
	}
	for _, port := range []string{"22", fmt.Sprint(tunnelPort)} {
		found := false
		for _, r := range rules {
			if r.IPType == "v4" && r.Protocol == "tcp" && r.Subnet == bridgeIP && r.Size == 32 && r.Port == port {
				found = true
			}
		}
		if !found {
			if e = v.request(ctx, "POST", "/firewalls/"+url.PathEscape(id)+"/rules", rule{IPType: "v4", Protocol: "tcp", Subnet: bridgeIP, Size: 32, Port: port}, nil); e != nil {
				return "", e
			}
		}
	}
	return id, nil
}
func (v *Vultr) DeleteFirewall(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	e := v.request(ctx, "DELETE", "/firewalls/"+url.PathEscape(id), nil, nil)
	var api APIError
	if errors.As(e, &api) && api.Status == 404 {
		return nil
	}
	return e
}

func (v *Vultr) request(ctx context.Context, method, path string, input, output any) error {
	for attempt := 0; ; attempt++ {
		e := v.requestOnce(ctx, method, path, input, output)
		if e == nil {
			return nil
		}
		if method != "GET" || attempt >= 2 {
			return e
		}
		var status APIError
		if errors.As(e, &status) && status.Status > 0 && status.Status != 429 && status.Status < 500 {
			return e
		}
		select {
		case <-ctx.Done():
			return ErrUnavailable
		case <-time.After(time.Duration(attempt+1) * 300 * time.Millisecond):
		}
	}
}

func (v *Vultr) Ubuntu2404(ctx context.Context) (int, error) {
	type system struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		Arch string `json:"arch"`
	}
	systems, e := list[system](ctx, v, "/os", "os")
	if e != nil {
		return 0, e
	}
	for _, s := range systems {
		if s.Name == "Ubuntu 24.04 LTS x64" && s.Arch == "x64" {
			return s.ID, nil
		}
	}
	return 0, errors.New("ubuntu 24.04 LTS x64 unavailable")
}
