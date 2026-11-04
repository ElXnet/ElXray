package dispatcher

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/subscriptionrate"
	"github.com/xtls/xray-core/features/policy"
)

func subscriptionLimits(ctx context.Context, manager policy.Manager) *subscriptionrate.Limits {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || inbound.User == nil {
		return nil
	}
	if provider, ok := manager.(policy.SubscriptionManager); ok {
		return provider.ForEmail(inbound.User.Email)
	}
	return nil
}

// waitRate chunks reservations so a large MultiBuffer never exceeds the burst.
func waitRate(ctx context.Context, limiter *subscriptionrate.Budget, size int32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for size > 0 {
		n := min(int(size), subscriptionrate.Burst)
		if err := limiter.WaitN(ctx, n); err != nil {
			return err
		}
		size -= int32(n)
	}
	return nil
}

// RateWriter enforces a shared byte budget before passing ownership downstream.
type RateWriter struct {
	writer  buf.Writer
	limiter *subscriptionrate.Budget
	ctx     context.Context
	cancel  context.CancelFunc
}

func newRateWriter(ctx context.Context, writer buf.Writer, limiter *subscriptionrate.Budget) *RateWriter {
	ctx, cancel := context.WithCancel(ctx)
	return &RateWriter{writer: writer, limiter: limiter, ctx: ctx, cancel: cancel}
}

// RequiresBufferedCopy prevents raw socket splice from bypassing this writer.
func (*RateWriter) RequiresBufferedCopy() bool { return true }

func (w *RateWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// Send one buffer at a time to avoid holding a large write until its entire
	// reservation has elapsed. Buffer boundaries (including UDP metadata) survive.
	for len(mb) > 0 {
		var chunk buf.MultiBuffer
		mb, chunk = takeRateChunk(mb)
		size := chunk.Len()
		if err := waitRate(w.ctx, w.limiter, size); err != nil {
			buf.ReleaseMulti(chunk)
			buf.ReleaseMulti(mb)
			return err
		}
		if err := w.writer.WriteMultiBuffer(chunk); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		w.limiter.RecordPayload(size)
	}
	return nil
}

func (w *RateWriter) Close() error {
	w.cancel()
	return common.Close(w.writer)
}

func (w *RateWriter) Interrupt() {
	w.cancel()
	common.Interrupt(w.writer)
}

type rateReader struct {
	reader     buf.Reader
	limiter    *subscriptionrate.Budget
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	pending    buf.MultiBuffer
	pendingErr error
}

func newRateReader(ctx context.Context, reader buf.Reader, limiter *subscriptionrate.Budget) *rateReader {
	ctx, cancel := context.WithCancel(ctx)
	return &rateReader{reader: reader, limiter: limiter, ctx: ctx, cancel: cancel}
}

func (r *rateReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.ctx.Err(); err != nil {
		r.Interrupt()
		return nil, err
	}
	r.mu.Lock()
	empty := len(r.pending) == 0
	r.mu.Unlock()
	if empty {
		mb, err := r.reader.ReadMultiBuffer()
		r.mu.Lock()
		r.pending, r.pendingErr = mb, err
		r.mu.Unlock()
	}
	r.mu.Lock()
	var chunk buf.MultiBuffer
	r.pending, chunk = takeRateChunk(r.pending)
	var err error
	if len(r.pending) == 0 {
		err, r.pendingErr = r.pendingErr, nil
	}
	r.mu.Unlock()
	if limitErr := waitRate(r.ctx, r.limiter, chunk.Len()); limitErr != nil {
		buf.ReleaseMulti(chunk)
		r.Interrupt()
		return nil, limitErr
	}
	r.limiter.RecordPayload(chunk.Len())
	return chunk, err
}

func (r *rateReader) Interrupt() {
	r.cancel()
	r.mu.Lock()
	r.pending = buf.ReleaseMulti(r.pending)
	r.mu.Unlock()
	common.Interrupt(r.reader)
}

func (r *rateReader) Close() error {
	r.Interrupt()
	return nil
}

func takeRateChunk(mb buf.MultiBuffer) (buf.MultiBuffer, buf.MultiBuffer) {
	// SingleReader is allowed to return MultiBuffer{nil} together with EOF.
	for len(mb) > 0 && mb[0] == nil {
		mb = mb[1:]
	}
	if len(mb) == 0 {
		return nil, nil
	}
	if mb[0].UDP != nil || mb[0].Len() <= subscriptionrate.Burst {
		// Keep datagrams whole and never coalesce a following nil sentinel into
		// the result. Several downstream writers dereference each buffer.
		rest, first := buf.SplitFirst(mb)
		return rest, buf.MultiBuffer{first}
	}
	return buf.SplitSize(mb, subscriptionrate.Burst)
}
