package trace

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		body       string
		wantStage  string
		wantDetail string
	}{
		{
			body:      "proxy/vless/inbound: firstLen = 1186",
			wantStage: StageClientFirstByte,
		},
		{
			body:       "app/dispatcher: sniffed domain: zws2.web.telegram.org",
			wantStage:  StageDomainSniffed,
			wantDetail: "zws2.web.telegram.org",
		},
		{
			body:       "app/dispatcher: taking detour [to-exit] for [tcp:zws2.web.telegram.org:443]",
			wantStage:  StageRoutingDecision,
			wantDetail: "to-exit → tcp:zws2.web.telegram.org:443",
		},
		{
			body:       "app/dispatcher: Hit route rule: [rule1] so taking detour [direct] for [tcp:yandex.ru:443]",
			wantStage:  StageRoutingDecision,
			wantDetail: "direct → tcp:yandex.ru:443",
		},
		{
			body:       "transport/internet/splithttp: XHTTP is dialing to tcp:94.103.81.225:51001, mode stream-up, HTTP version 2",
			wantStage:  StageDialExitStart,
			wantDetail: "tcp:94.103.81.225:51001",
		},
		{
			body:       "proxy/vless/outbound: tunneling request to tcp:zws2.web.telegram.org:443 via 94.103.81.225:51001",
			wantStage:  StageTunnelUp,
			wantDetail: "tcp:zws2.web.telegram.org:443 via 94.103.81.225:51001",
		},
		{
			body:       "proxy/socks: connecting to tcp:example.com:443 via socks5://127.0.0.1:40000",
			wantStage:  StageWARPDialStart,
			wantDetail: "tcp:example.com:443",
		},
		{
			body:      "proxy/freedom/outbound: connecting to tcp:8.8.8.8:53",
			wantStage: StageDirectDialStart,
		},
		{
			body:      "proxy/vless/inbound: received request for tcp:1.2.3.4:443",
			wantStage: "", // not a classified event
		},
	}

	for _, tt := range tests {
		label := tt.body
		if len(label) > 40 {
			label = label[:40]
		}
		t.Run(label, func(t *testing.T) {
			got, detail := classify(tt.body)
			if got != tt.wantStage {
				t.Errorf("stage: got %q want %q", got, tt.wantStage)
			}
			if tt.wantDetail != "" && detail != tt.wantDetail {
				t.Errorf("detail: got %q want %q", detail, tt.wantDetail)
			}
		})
	}
}

func TestLogLineRE(t *testing.T) {
	line := "[1024478894] app/dispatcher: taking detour [to-exit] for [tcp:example.com:443]"
	m := logLineRE.FindStringSubmatch(line)
	if m == nil {
		t.Fatal("regex did not match")
	}
	if m[1] != "1024478894" {
		t.Errorf("session ID: got %q want %q", m[1], "1024478894")
	}
}

func TestStoreAppendAndRecent(t *testing.T) {
	store := NewStore()
	defer store.Close()

	ts := time.Now()
	store.Append(42, Event{At: ts, Stage: StageClientFirstByte})
	store.Append(42, Event{At: ts.Add(1 * time.Millisecond), Stage: StageDomainSniffed, Detail: "example.com"})
	store.Append(42, Event{At: ts.Add(2 * time.Millisecond), Stage: StageRoutingDecision, Detail: "to-exit → tcp:example.com:443"})
	store.Append(42, Event{At: ts.Add(30 * time.Millisecond), Stage: StageTunnelUp, Detail: "tcp:example.com:443 via 1.2.3.4:51001"})

	recent := store.Recent(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 completed session, got %d", len(recent))
	}
	s := recent[0]
	if s.ID != 42 {
		t.Errorf("session ID: got %d want 42", s.ID)
	}
	if s.Destination != "example.com" {
		t.Errorf("destination: got %q want %q", s.Destination, "example.com")
	}
	deltas := s.StageDeltasMS()
	if deltas[StageTunnelUp] != 30 {
		t.Errorf("tunnel_up delta: got %d want 30", deltas[StageTunnelUp])
	}
}

func TestStoreActiveEviction(t *testing.T) {
	store := NewStore()
	defer store.Close()

	// Append only a start event — no terminal event, so it stays in active.
	store.Append(99, Event{At: time.Now(), Stage: StageClientFirstByte})
	if len(store.Active()) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(store.Active()))
	}
	// No completed sessions yet.
	if len(store.Recent(10)) != 0 {
		t.Fatalf("expected 0 completed sessions")
	}
}
