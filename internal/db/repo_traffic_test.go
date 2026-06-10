package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTrafficBucketExpr(t *testing.T) {
	tests := []struct {
		bucket  string
		wantErr bool
	}{
		{bucket: "5m"},
		{bucket: "1h"},
		{bucket: "6h"},
		{bucket: "1d"},
		{bucket: "bad", wantErr: true},
	}
	for _, tc := range tests {
		got, err := trafficBucketExpr(tc.bucket)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("expected error for bucket %q, got expr=%q", tc.bucket, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tc.bucket, err)
		}
		if got == "" {
			t.Fatalf("empty expression for bucket %q", tc.bucket)
		}
	}
}

func TestTrafficTimelineByBuckets(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewTrafficRepo(database)

	userUUID := uuid.NewString()
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE uuid=$1`, userUUID)
	})
	if _, err := database.Pool.Exec(ctx, `INSERT INTO users(uuid, name) VALUES($1, 'traffic-timeline-test')`, userUUID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	now := time.Now().UTC()
	hourStart := now.Truncate(time.Hour)
	samples := []TrafficSample{
		{UserUUID: userUUID, CollectedAt: hourStart.Add(5 * time.Minute), UplinkBytes: 100, DownlinkBytes: 200},
		{UserUUID: userUUID, CollectedAt: hourStart.Add(35 * time.Minute), UplinkBytes: 300, DownlinkBytes: 400},
	}
	if err := repo.RecordSamples(ctx, samples); err != nil {
		t.Fatalf("record samples: %v", err)
	}

	points, err := repo.TrafficTimelineByBuckets(ctx, userUUID, time.Hour, "1h")
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("point count=%d, want 1: %+v", len(points), points)
	}
	if points[0].UplinkBytes != 400 || points[0].DownlinkBytes != 600 || points[0].TotalBytes != 1000 {
		t.Fatalf("unexpected totals: %+v", points[0])
	}
}
