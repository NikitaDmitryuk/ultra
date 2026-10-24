package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

type fakeCensusProvider struct {
	rows    []cloud.Instance
	listErr error
	get     func(string) (cloud.Instance, error)
}

func (p fakeCensusProvider) Instances(context.Context) ([]cloud.Instance, error) {
	return p.rows, p.listErr
}
func (p fakeCensusProvider) Get(_ context.Context, id string) (cloud.Instance, error) {
	return p.get(id)
}

func TestProviderCensusAbsenceRequiresExplicit404AndCompleteAgreement(t *testing.T) {
	live := cloud.Instance{ID: "live", IP: "192.0.2.1", Tags: []string{"private-label"}, Region: "private-region"}
	for _, scenario := range []string{"valid", "list-failed", "forbidden", "transient", "listed-disappeared", "unlisted-appeared", "changed-address", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			p := fakeCensusProvider{rows: []cloud.Instance{live}}
			p.get = func(id string) (cloud.Instance, error) {
				if id == "live" {
					if scenario == "listed-disappeared" {
						return cloud.Instance{}, cloud.APIError{Status: 404}
					}
					if scenario == "changed-address" {
						v := live
						v.IP = "192.0.2.2"
						return v, nil
					}
					return live, nil
				}
				switch scenario {
				case "forbidden":
					return cloud.Instance{}, cloud.APIError{Status: 403}
				case "transient":
					return cloud.Instance{}, errors.New("credential secret must not escape")
				case "unlisted-appeared":
					return cloud.Instance{ID: id, IP: "192.0.2.2"}, nil
				}
				return cloud.Instance{}, cloud.APIError{Status: 404}
			}
			if scenario == "list-failed" {
				p.listErr = errors.New("unavailable")
			}
			if scenario == "duplicate" {
				p.rows = append(p.rows, live)
			}
			r, err := collectProviderCensus(context.Background(), p, []string{"live", "deleted"}, strings.Repeat("a", 64))
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("incorrect admission: %v", err)
			}
			if err != nil && (!strings.HasPrefix(err.Error(), "provider_census_") || strings.Contains(err.Error(), "secret")) {
				t.Fatal("unredacted failure")
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "private-") {
				t.Fatal("unnecessary provider metadata leaked")
			}
			if scenario == "valid" && (r.ObservedAt == 0 || r.Requested[0].Present || !r.Requested[1].Present) {
				t.Fatal("wrong proof")
			}
		})
	}
}

func TestProviderCensusRejectsAmbiguousIDs(t *testing.T) {
	for _, ids := range [][]string{nil, {"a", "a"}, {"../instances"}, {"a?x=y"}} {
		if _, err := collectProviderCensus(context.Background(), fakeCensusProvider{}, ids, strings.Repeat("a", 64)); err == nil {
			t.Fatal("invalid IDs admitted")
		}
	}
}
