package db

import "testing"

func TestBucketExpr(t *testing.T) {
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
		got, err := bucketExpr(tc.bucket)
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
