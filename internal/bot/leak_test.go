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

func TestCollectOnlineIPList(t *testing.T) {
	uA := "11111111-1111-1111-1111-111111111111"
	uB := "22222222-2222-2222-2222-222222222222"
	srv := &fakeStatsServer{
		users: map[string]map[string]int64{
			uA: {"1.1.1.1": 1, "8.8.8.8": 1},
			uB: {"9.9.9.9": 1},
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
		t.Fatalf("user A IPs mismatch: %#v", a)
	}
	if len(got[uB]) != 1 || got[uB][0] != "9.9.9.9" {
		t.Fatalf("user B IPs mismatch: %#v", got[uB])
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
