package dispatcher

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/subscriptionrate"
)

type rateBarrierHeldSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *rateBarrierHeldSink) WriteMultiBuffer(payload buf.MultiBuffer) error {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	buf.ReleaseMulti(payload)
	return nil
}

func TestRateWriterQuietBarrierWaitsForInFlightDelivery(t *testing.T) {
	limits := subscriptionrate.New(1000, 1000)
	sink := &rateBarrierHeldSink{entered: make(chan struct{}), release: make(chan struct{})}
	writer := newRateWriter(context.Background(), sink, limits.Uplink)
	defer writer.Close()
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("in flight"))})
	}()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("test payload did not enter dispatcher sink")
	}
	proved := make(chan struct{}, 1)
	barrierResult := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	go func() {
		_, err := limits.WithQuietRateBarrier(ctx, func() ([]byte, error) {
			proved <- struct{}{}
			return []byte("signed"), nil
		})
		barrierResult <- err
	}()
	select {
	case <-proved:
		t.Fatal("proof signed before old-rate bytes left the dispatcher sink")
	case err := <-barrierResult:
		t.Fatalf("barrier completed with old payload pending: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	limits.Update(100, 100, false)
	close(sink.release)
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("held rate write did not complete")
	}
	select {
	case err := <-barrierResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("quiet barrier failed to finish after the in-flight write")
	}
	// Keep using the very same writer and limits: no re-handshake required.
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("next"))}); err != nil {
		t.Fatalf("existing VPN stream stopped after rate reduction: %v", err)
	}
}

func TestRateReaderWaitsThroughQuietBarrierWithoutDroppingPayload(t *testing.T) {
	limits := subscriptionrate.New(1000, 1000)
	reader := newRateReader(context.Background(), &finalBufferReader{
		payload: buf.MultiBuffer{buf.FromBytes([]byte("preserved"))},
	}, limits.Uplink)
	defer reader.Close()
	entered := make(chan struct{})
	releaseProof := make(chan struct{})
	barrierDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	go func() {
		_, err := limits.WithQuietRateBarrier(ctx, func() ([]byte, error) {
			close(entered)
			<-releaseProof
			return []byte("proof"), nil
		})
		barrierDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("quiet read barrier not established")
	}
	type received struct {
		payload buf.MultiBuffer
		err     error
	}
	result := make(chan received, 1)
	go func() {
		mb, err := reader.ReadMultiBuffer()
		result <- received{payload: mb, err: err}
	}()
	select {
	case got := <-result:
		buf.ReleaseMulti(got.payload)
		t.Fatalf("reader bypassed quiet rate gate: %v", got.err)
	case <-time.After(20 * time.Millisecond):
	}
	limits.Update(200, 200, false)
	close(releaseProof)
	if err := <-barrierDone; err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		size := got.payload.Len()
		// The fixture returns the final bytes together with io.EOF. That
		// is a normal Reader contract, not a lost or disconnected stream.
		if (got.err != nil && got.err != io.EOF) || size != int32(len("preserved")) {
			buf.ReleaseMulti(got.payload)
			t.Fatalf("payload lost across quiet barrier: %v, %d", got.err, size)
		}
		buf.ReleaseMulti(got.payload)
	case <-ctx.Done():
		t.Fatal("reader did not resume after signed rate barrier")
	}
}
