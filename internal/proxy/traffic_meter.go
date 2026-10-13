package proxy

import (
	"context"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"strings"
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
	values   map[[2]string]*routeCount
	store    *runtimestate.Store
	accounts map[string]string
}
type routeCount struct {
	up, down atomic.Int64
	refs     int
}
type meteredContext struct{}
type measuredOutbound struct {
	outbound.Handler
	meter     *routeMeter
	lifecycle sync.Mutex
	closing   bool
	active    sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
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

// Close terminates streams owned by this instance, not just listening sockets.
func (h *measuredOutbound) Close() error {
	h.lifecycle.Lock()
	h.closing = true
	if h.cancel != nil {
		h.cancel()
	}
	h.lifecycle.Unlock()
	err := h.Handler.Close()
	h.active.Wait()
	return err
}
func (h *measuredOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	h.lifecycle.Lock()
	if h.closing {
		h.lifecycle.Unlock()
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
		return
	}
	h.active.Add(1)
	h.lifecycle.Unlock()
	defer h.active.Done()
	if h.ctx != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		stop := context.AfterFunc(h.ctx, func() { cancel(); _ = common.Interrupt(link.Reader); _ = common.Interrupt(link.Writer) })
		defer stop()
		defer cancel()
	}

	in := session.InboundFromContext(ctx)
	if ctx.Value(meteredContext{}) != nil || in == nil || in.User == nil {
		h.Handler.Dispatch(ctx, link)
		return
	}
	if _, e := uuid.Parse(in.User.Email); e != nil {
		h.Handler.Dispatch(ctx, link)
		return
	}
	h.meter.Lock()
	account := h.meter.accounts[in.User.Email]
	store := h.meter.store
	h.meter.Unlock()
	owner := in.User.Email
	if store != nil {
		if account == "" {
			_ = common.Interrupt(link.Reader)
			_ = common.Interrupt(link.Writer)
			return
		}
		owner = account
	}
	leaseStore := store
	exitID := strings.TrimPrefix(h.Tag(), "to-exit-")
	if exitID == h.Tag() {
		store = nil
	}
	count := h.meter.acquire(owner, h.Tag())
	defer func() { h.meter.Lock(); count.refs--; h.meter.Unlock() }()
	reader := &measuredReader{Reader: link.Reader, counter: &count.up, store: store, leaseStore: leaseStore, account: account, exit: exitID}
	measured := &transport.Link{Reader: reader, Writer: link.Writer}
	if timed, ok := link.Reader.(buf.TimeoutReader); ok {
		measured.Reader = &measuredTimeoutReader{measuredReader: reader, timed: timed}
	}
	// Limited flows hide the raw inbound connection from Xray. Its Linux
	// splice can bypass buf.Writer entirely, even when the writer is wrapped.
	if leaseStore != nil {
		ctx = withoutSplice(ctx)
	}
	// Preserve the concrete stats writer only for unrestricted flows.
	if leaseStore != nil {
		measured.Writer = &limitedWriter{Writer: link.Writer, counter: &count.down, store: store, leaseStore: leaseStore, account: account, exit: exitID}
	} else if writer, ok := link.Writer.(*dispatcher.SizeStatWriter); ok {
		measured.Writer = &dispatcher.SizeStatWriter{Writer: writer.Writer, Counter: dualCounter{Counter: writer.Counter, extra: &count.down}}
	} else {
		measured.Writer = &dispatcher.SizeStatWriter{Writer: link.Writer, Counter: atomicCounter{&count.down}}
	}
	h.Handler.Dispatch(context.WithValue(ctx, meteredContext{}, true), measured)
}

type measuredReader struct {
	buf.Reader
	counter       *atomic.Int64
	store         *runtimestate.Store
	leaseStore    *runtimestate.Store
	account, exit string
}

func (r *measuredReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, e := r.Reader.ReadMultiBuffer()
	if err := authorizeFlow(r.store, r.leaseStore, r.account, r.exit, int64(b.Len())); err != nil {
		buf.ReleaseMulti(b)
		return nil, err
	}
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
	if err := authorizeFlow(r.store, r.leaseStore, r.account, r.exit, int64(b.Len())); err != nil {
		buf.ReleaseMulti(b)
		return nil, err
	}
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
		ctx, cancel := context.WithCancel(context.Background())
		if e := manager.AddHandler(context.Background(), &measuredOutbound{Handler: h, meter: meter, ctx: ctx, cancel: cancel}); e != nil {
			cancel()
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

// configure is called before loading a new core; active streams retain their stable owner.
func (m *routeMeter) configure(store *runtimestate.Store, users []auth.User) error {
	accounts := map[string]string{}
	for _, u := range users {
		if u.AccountID == "" {
			return errors.New("missing accounting identity")
		}
		accounts[u.UUID] = u.AccountID
		for _, v := range u.Routes {
			accounts[v.UUID] = u.AccountID
		}
	}
	m.Lock()
	m.store = store
	m.accounts = accounts
	m.Unlock()
	return nil
}
func authorize(store *runtimestate.Store, account, exit string, n int64) error {
	if store == nil {
		return nil
	}
	for n > 0 {
		grant, err := store.Reserve(account, exit, n)
		if err != nil {
			return err
		}
		if grant <= 0 {
			return runtimestate.ErrQuota
		}
		n -= grant
	}
	return nil
}

type limitedWriter struct {
	buf.Writer
	counter       *atomic.Int64
	store         *runtimestate.Store
	leaseStore    *runtimestate.Store
	account, exit string
}

func (w *limitedWriter) WriteMultiBuffer(b buf.MultiBuffer) error {
	n := int64(b.Len())
	if err := authorizeFlow(w.store, w.leaseStore, w.account, w.exit, n); err != nil {
		buf.ReleaseMulti(b)
		return err
	}
	w.counter.Add(n)
	return w.Writer.WriteMultiBuffer(b)
}
func (w *limitedWriter) Interrupt()   { _ = common.Interrupt(w.Writer) }
func (w *limitedWriter) Close() error { return common.Close(w.Writer) }

func withoutSplice(ctx context.Context) context.Context {
	if in := session.InboundFromContext(ctx); in != nil {
		copy := *in
		copy.Conn = nil
		copy.CanSpliceCopy = 3
		return session.ContextWithInbound(ctx, &copy)
	}
	return ctx
}

func authorizeFlow(store, leaseStore *runtimestate.Store, account, exit string, n int64) error {
	if n == 0 {
		return nil
	}
	if store == nil && leaseStore != nil {
		return leaseStore.ValidateAuthorization(account)
	}
	return authorize(store, account, exit, n)
}

// DrainAccountTraffic uses immutable owner identifiers, including streams whose
// credentials were rotated or deleted after their outbound was opened.
func (r *Runner) DrainAccountTraffic() map[string]map[string][2]int64 {
	r.mu.Lock()
	m := r.meter
	r.mu.Unlock()
	if m == nil {
		return nil
	}
	m.Lock()
	configured := m.store != nil
	m.Unlock()
	if !configured {
		return nil
	}
	return m.drain()
}
