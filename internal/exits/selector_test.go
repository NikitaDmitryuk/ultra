package exits

import (
	"context"
	"testing"
	"time"
)

func TestSelectorRoutesNotMeasurements(t *testing.T) {
	now := time.Unix(1000, 0)
	failed := false
	rtt := int64(1)
	s := NewSelector(func(_ context.Context, n Node) Health {
		return Health{Reachable: true, InternetOK: !failed || n.ID != "a", TunnelLatencyMS: rtt}
	})
	s.now = func() time.Time { return now }
	nodes := []Node{{ID: "a", Enabled: true, Priority: 1}, {ID: "b", Enabled: true, Priority: 2}}
	for range 3 {
		s.ProbeAndSelect(context.Background(), nodes)
		now = now.Add(10 * time.Second)
	}
	now = now.Add(time.Minute)
	s.ProbeAndSelect(context.Background(), nodes)
	rtt = 200
	if _, changed := s.ProbeAndSelect(context.Background(), nodes); changed {
		t.Fatal("RTT caused route change")
	}
	failed = true
	if active, _ := s.ProbeAndSelect(context.Background(), nodes); active.ID != "a" {
		t.Fatal("switched after one failure")
	}
	if active, _ := s.ProbeAndSelect(context.Background(), nodes); active.ID != "b" {
		t.Fatal("did not fail over after two failures")
	}
	failed = false
	for range 3 {
		s.ProbeAndSelect(context.Background(), nodes)
		now = now.Add(10 * time.Second)
	}
	if s.ActiveID() != "b" {
		t.Fatal("failback before stability window")
	}
	now = now.Add(time.Minute)
	if active, _ := s.ProbeAndSelect(context.Background(), nodes); active.ID != "a" {
		t.Fatal("no failback")
	}
}

func TestSelectorCancellationAndParallelism(t *testing.T) {
	entered := make(chan string, 2)
	s := NewSelector(func(ctx context.Context, n Node) Health {
		entered <- n.ID
		if n.ID == "a" {
			<-ctx.Done()
		}
		return Health{InternetOK: n.ID == "b"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.ProbeAndSelect(ctx, []Node{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}}); close(done) }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("serial probes")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation ignored")
	}
	if len(s.HealthSnapshot()) != 0 {
		t.Fatal("cancellation became health failure")
	}
}

func TestAllExitsFailRemainTunneled(t *testing.T) {
	s := NewSelector(func(context.Context, Node) Health { return Health{Reachable: true} })
	nodes := []Node{{ID: "a", Enabled: true, Priority: 1}, {ID: "b", Enabled: true, Priority: 2}}
	for range 3 {
		s.ProbeAndSelect(context.Background(), nodes)
	}
	if s.ActiveID() != "a" {
		t.Fatal("lost tunnel fallback")
	}
	for _, h := range s.HealthSnapshot() {
		if h.Eligible {
			t.Fatal("TCP alone eligible")
		}
	}
}
