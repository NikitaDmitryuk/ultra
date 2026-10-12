package proxy

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type quotaReader struct{ data []byte }

func (r quotaReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	_, _ = b.Write(r.data)
	return buf.MultiBuffer{b}, io.EOF
}

type quotaWriter struct{ received int }

func (w *quotaWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	w.received += int(b.Len())
	buf.ReleaseMulti(b)
	return nil
}
func TestBothDirectionsSharePretransferQuota(t *testing.T) {
	store, e := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = store.Close() }()
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{{AccountID: "owner", ExitID: "exit", Period: now.Format("2006-01"), LimitBytes: 5, ExpiresAt: now.Add(time.Hour)}, {ExitID: "exit", Period: now.Format("2006-01"), LimitBytes: 5, ExpiresAt: now.Add(time.Hour)}}
	if e = store.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: []byte(`{}`)}, limits); e != nil {
		t.Fatal(e)
	}
	counter := atomic.Int64{}
	reader := &measuredReader{Reader: quotaReader{[]byte("abc")}, counter: &counter, store: store, account: "owner", exit: "exit"}
	b, e := reader.ReadMultiBuffer()
	if !errors.Is(e, io.EOF) || b.Len() != 3 {
		t.Fatalf("reader %d %v", b.Len(), e)
	}
	buf.ReleaseMulti(b)
	dest := &quotaWriter{}
	writer := &limitedWriter{Writer: dest, counter: &counter, store: store, account: "owner", exit: "exit"}
	packet := buf.New()
	_, _ = packet.Write([]byte("def"))
	if e = writer.WriteMultiBuffer(buf.MultiBuffer{packet}); !errors.Is(e, runtimestate.ErrQuota) {
		t.Fatalf("overquota writer %v", e)
	}
	if dest.received != 0 {
		t.Fatal("sent bytes before authorization")
	}
}

func TestLimitedContextHidesRawConnectionFromVisionSplice(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	original := &session.Inbound{Conn: left, CanSpliceCopy: 2}
	ctx := session.ContextWithInbound(context.Background(), original)
	limited := session.InboundFromContext(withoutSplice(ctx))
	if limited == original || limited.Conn != nil || limited.CanSpliceCopy != 3 {
		t.Fatal("raw connection available for splice")
	}
	if original.Conn != left || original.CanSpliceCopy != 2 {
		t.Fatal("mutated upstream metadata")
	}
}
