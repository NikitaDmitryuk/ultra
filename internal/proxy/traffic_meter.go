package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

type routeMeter struct {
	sync.Mutex
	values map[[2]string]*routeCount
}
type routeCount struct {
	up, down atomic.Int64
	refs     int
}
type meteredContext struct{}
type measuredOutbound struct {
	outbound.Handler
	meter *routeMeter
}

func (m *routeMeter) acquire(user, tag string) *routeCount {
	m.Lock()
	defer m.Unlock()
	if m.values == nil {
		m.values = map[[2]string]*routeCount{}
	}
	key := [2]string{user, tag}
	v := m.values[key]
	if v == nil {
		v = &routeCount{}
		m.values[key] = v
	}
	v.refs++
	return v
}
func (m *routeMeter) drain() map[string]map[string][2]int64 {
	m.Lock()
	defer m.Unlock()
	out := map[string]map[string][2]int64{}
	for key, v := range m.values {
		up, down := v.up.Swap(0), v.down.Swap(0)
		if up != 0 || down != 0 {
			if out[key[0]] == nil {
				out[key[0]] = map[string][2]int64{}
			}
			out[key[0]][key[1]] = [2]int64{up, down}
		}
		if v.refs == 0 {
			delete(m.values, key)
		}
	}
	return out
}
func (h *measuredOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	in := session.InboundFromContext(ctx)
	if ctx.Value(meteredContext{}) != nil || in == nil || in.User == nil {
		h.Handler.Dispatch(ctx, link)
		return
	}
	if _, e := uuid.Parse(in.User.Email); e != nil {
		h.Handler.Dispatch(ctx, link)
		return
	}
	count := h.meter.acquire(in.User.Email, h.Tag())
	defer func() { h.meter.Lock(); count.refs--; h.meter.Unlock() }()
	reader := &measuredReader{Reader: link.Reader, counter: &count.up}
	measured := &transport.Link{Reader: reader, Writer: link.Writer}
	if timed, ok := link.Reader.(buf.TimeoutReader); ok {
		measured.Reader = &measuredTimeoutReader{measuredReader: reader, timed: timed}
	}
	// Preserve the concrete writer type used by Xray's Linux Vision splice path.
	if writer, ok := link.Writer.(*dispatcher.SizeStatWriter); ok {
		measured.Writer = &dispatcher.SizeStatWriter{Writer: writer.Writer, Counter: dualCounter{Counter: writer.Counter, extra: &count.down}}
	} else {
		measured.Writer = &dispatcher.SizeStatWriter{Writer: link.Writer, Counter: atomicCounter{&count.down}}
	}
	h.Handler.Dispatch(context.WithValue(ctx, meteredContext{}, true), measured)
}

type measuredReader struct {
	buf.Reader
	counter *atomic.Int64
}

func (r *measuredReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, e := r.Reader.ReadMultiBuffer()
	r.counter.Add(int64(b.Len()))
	return b, e
}
func (r *measuredReader) Interrupt()   { _ = common.Interrupt(r.Reader) }
func (r *measuredReader) Close() error { return common.Close(r.Reader) }

type measuredTimeoutReader struct {
	*measuredReader
	timed buf.TimeoutReader
}

func (r *measuredTimeoutReader) ReadMultiBufferTimeout(t time.Duration) (buf.MultiBuffer, error) {
	b, e := r.timed.ReadMultiBufferTimeout(t)
	r.counter.Add(int64(b.Len()))
	return b, e
}

type atomicCounter struct{ n *atomic.Int64 }

func (c atomicCounter) Value() int64      { return c.n.Load() }
func (c atomicCounter) Set(v int64) int64 { return c.n.Swap(v) }
func (c atomicCounter) Add(v int64) int64 { return c.n.Add(v) - v }

type dualCounter struct {
	stats.Counter
	extra *atomic.Int64
}

func (c dualCounter) Add(v int64) int64 { c.extra.Add(v); return c.Counter.Add(v) }
func attachRouteMeter(inst *core.Instance, meter *routeMeter) error {
	manager, ok := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if !ok {
		return nil
	}
	handlers := manager.ListHandlers(context.Background())
	// RemoveHandler does not close the handler in the pinned Xray. Replace before Start.
	for _, h := range handlers {
		if h.Tag() == "" {
			continue
		}
		if e := manager.RemoveHandler(context.Background(), h.Tag()); e != nil {
			return e
		}
		if e := manager.AddHandler(context.Background(), &measuredOutbound{Handler: h, meter: meter}); e != nil {
			return e
		}
	}
	return nil
}

// DrainRouteTraffic survives core reloads; only byte deltas, never destination addresses.
func (r *Runner) DrainRouteTraffic() map[string]map[string][2]int64 {
	r.mu.Lock()
	m := r.meter
	r.mu.Unlock()
	if m == nil {
		return nil
	}
	return m.drain()
}
