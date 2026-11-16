package settlement

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLedgerRingBuffer_BatchFlushOnThreshold(t *testing.T) {
	var flushedCount int64
	var batchCalls int64

	flushFunc := func(ctx context.Context, events []*BatchSettlementEvent) error {
		atomic.AddInt64(&flushedCount, int64(len(events)))
		atomic.AddInt64(&batchCalls, 1)
		return nil
	}

	rb := NewLedgerRingBuffer(RingBufferConfig{
		BufferSize:    1000,
		BatchSize:     10,
		FlushInterval: 1 * time.Second, // Long timer so threshold triggers first
		FlushHandler:  flushFunc,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb.Start(ctx)

	// Enqueue 25 items
	for i := 0; i < 25; i++ {
		ok := rb.Enqueue(&BatchSettlementEvent{
			EventID:      "evt_test",
			TenantID:     "ten_01",
			ActualAmount: 100,
		})
		if !ok {
			t.Fatalf("failed to enqueue event %d", i)
		}
	}

	// Give worker time to flush two batches of 10
	time.Sleep(50 * time.Millisecond)

	count := atomic.LoadInt64(&flushedCount)
	if count < 20 {
		t.Fatalf("expected at least 20 events flushed via threshold, got %d", count)
	}

	// Close should flush the remaining 5 items
	if err := rb.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	finalCount := atomic.LoadInt64(&flushedCount)
	if finalCount != 25 {
		t.Fatalf("expected all 25 events flushed on close, got %d", finalCount)
	}
}

func TestLedgerRingBuffer_TimerFlush(t *testing.T) {
	var flushedCount int64

	var wg sync.WaitGroup
	wg.Add(1)

	flushFunc := func(ctx context.Context, events []*BatchSettlementEvent) error {
		atomic.AddInt64(&flushedCount, int64(len(events)))
		wg.Done()
		return nil
	}

	rb := NewLedgerRingBuffer(RingBufferConfig{
		BufferSize:    1000,
		BatchSize:     100, // High batch size, so timer triggers first
		FlushInterval: 30 * time.Millisecond,
		FlushHandler:  flushFunc,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rb.Start(ctx)

	rb.Enqueue(&BatchSettlementEvent{
		EventID:      "evt_timer_test",
		ActualAmount: 50,
	})

	wg.Wait()

	if atomic.LoadInt64(&flushedCount) != 1 {
		t.Fatalf("expected 1 event flushed via timer")
	}

	_ = rb.Close()
}
