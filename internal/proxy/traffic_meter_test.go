package proxy

import (
	"bytes"
	"context"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"sync/atomic"
	"testing"
)

type fakeMeasuredHandler struct {
	outbound.Handler
	tag string
	t   *testing.T
}

func (h fakeMeasuredHandler) Tag() string { return h.tag }
func (h fakeMeasuredHandler) Dispatch(_ context.Context, link *transport.Link) {
	if _, ok := link.Writer.(*dispatcher.SizeStatWriter); !ok {
		h.t.Fatal("Vision-compatible writer lost")
	}
	b, e := link.Reader.ReadMultiBuffer()
	if e != nil {
		h.t.Fatal(e)
	}
	buf.ReleaseMulti(b)
	value := buf.New()
	_, _ = value.Write([]byte("reply"))
	if e = link.Writer.WriteMultiBuffer(buf.MultiBuffer{value}); e != nil {
		h.t.Fatal(e)
	}
}
func TestMeterUsesActualOutboundAndKeepsUserCounter(t *testing.T) {
	meter := &routeMeter{}
	user := "2784871e-d8a9-4e1f-b831-3d86aa8653ee"
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: user}})
	var original atomic.Int64
	for _, tag := range []string{"to-exit-a", "direct"} {
		var output bytes.Buffer
		h := measuredOutbound{Handler: fakeMeasuredHandler{tag: tag, t: t}, meter: meter}
		h.Dispatch(ctx, &transport.Link{Reader: buf.NewReader(bytes.NewBufferString("request")), Writer: &dispatcher.SizeStatWriter{Writer: buf.NewWriter(&output), Counter: atomicCounter{&original}}})
		if output.String() != "reply" {
			t.Fatal("payload changed")
		}
	}
	values := meter.drain()
	for _, tag := range []string{"to-exit-a", "direct"} {
		if values[user][tag] != [2]int64{7, 5} {
			t.Fatal("wrong route attribution", values)
		}
	}
	if original.Load() != 10 || len(meter.drain()) != 0 {
		t.Fatal("counter lost or double drained")
	}
}
