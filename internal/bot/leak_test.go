package bot

import (
	"context"
	"net"
	"sort"
	"testing"

	xraycmd "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type fakeStatsServer struct {
	xraycmd.UnimplementedStatsServiceServer
	users map[string]map[string]int64
}

func (s *fakeStatsServer) GetAllOnlineUsers(
	_ context.Context,
	_ *xraycmd.GetAllOnlineUsersRequest,
) (*xraycmd.GetAllOnlineUsersResponse, error) {
	out := make([]string, 0, len(s.users))
	for u := range s.users {
		out = append(out, u)
	}
	sort.Strings(out)
	return &xraycmd.GetAllOnlineUsersResponse{Users: out}, nil
}

func (s *fakeStatsServer) GetStatsOnlineIpList(
	_ context.Context,
	in *xraycmd.GetStatsRequest,
) (*xraycmd.GetStatsOnlineIpListResponse, error) {
	ips := s.users[in.GetName()]
	if ips == nil {
		ips = map[string]int64{}
	}
	return &xraycmd.GetStatsOnlineIpListResponse{Name: in.GetName(), Ips: ips}, nil
}

func startBufconnStats(t *testing.T, srv *fakeStatsServer) (xraycmd.StatsServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	xraycmd.RegisterStatsServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
	}
	return xraycmd.NewStatsServiceClient(conn), cleanup
}

// onlineKey returns the wire format used by Xray's dispatcher when registering
// online maps: "user>>>{email}>>>online". Test data must match this format,
// otherwise we'd silently regress to the original bug (mismatched keys → empty
// observations).
func onlineKey(email string) string { return onlineKeyPrefix + email + onlineKeySuffix }

func TestCollectOnlineIPList(t *testing.T) {
	uA := "11111111-1111-1111-1111-111111111111"
	uB := "22222222-2222-2222-2222-222222222222"
	srv := &fakeStatsServer{
		users: map[string]map[string]int64{
			onlineKey(uA): {"1.1.1.1": 1, "8.8.8.8": 1},
			onlineKey(uB): {"9.9.9.9": 1},
		},
	}
	client, cleanup := startBufconnStats(t, srv)
	defer cleanup()

	got, err := collectOnlineIPList(context.Background(), client)
	if err != nil {
		t.Fatalf("collectOnlineIPList: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 users, got %d: %#v", len(got), got)
	}
	a := append([]string(nil), got[uA]...)
	sort.Strings(a)
	if len(a) != 2 || a[0] != "1.1.1.1" || a[1] != "8.8.8.8" {
		t.Fatalf("user A IPs mismatch (map keyed by bare UUID expected): %#v", a)
	}
	if len(got[uB]) != 1 || got[uB][0] != "9.9.9.9" {
		t.Fatalf("user B IPs mismatch: %#v", got[uB])
	}
	// Sanity: the prefixed name should NOT leak into the output map.
	if _, present := got[onlineKey(uA)]; present {
		t.Fatalf("output must use bare UUID, not prefixed name; got %#v", got)
	}
}

func TestCollectOnlineIPList_Empty(t *testing.T) {
	client, cleanup := startBufconnStats(t, &fakeStatsServer{users: map[string]map[string]int64{}})
	defer cleanup()

	got, err := collectOnlineIPList(context.Background(), client)
	if err != nil {
		t.Fatalf("collectOnlineIPList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got: %#v", got)
	}
}

// TestCollectOnlineIPList_SkipsUnknownFormat guards against future xray-core
// changes: any entry that doesn't look like "user>>>...>>>online" is ignored
// instead of being misreported as a bare UUID.
func TestCollectOnlineIPList_SkipsUnknownFormat(t *testing.T) {
	srv := &fakeStatsServer{
		users: map[string]map[string]int64{
			"weirdname": {"5.5.5.5": 1},
			onlineKey("33333333-3333-3333-3333-333333333333"): {"1.2.3.4": 1},
		},
	}
	client, cleanup := startBufconnStats(t, srv)
	defer cleanup()

	got, err := collectOnlineIPList(context.Background(), client)
	if err != nil {
		t.Fatalf("collectOnlineIPList: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 user (unknown format dropped), got %d: %#v", len(got), got)
	}
	if _, ok := got["33333333-3333-3333-3333-333333333333"]; !ok {
		t.Fatalf("expected bare UUID key, got %#v", got)
	}
}
