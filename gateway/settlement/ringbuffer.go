package settlement

import (
	"context"
	"sync"
	"time"
)

// BatchSettlementEvent represents an individual transaction event to be settled in batch.
type BatchSettlementEvent struct {
	EventID          string    `json:"event_id"`
	TenantID         string    `json:"tenant_id"`
	WalletID         string    `json:"wallet_id"`
	RouteID          string    `json:"route_id"`
	ModelName        string    `json:"model_name"`
	HoldID           string    `json:"hold_id,omitempty"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	ActualAmount     int64     `json:"actual_amount"` // In micro-units
	TraceID          string    `json:"trace_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// BatchFlushFunc is the callback invoked to persist a batch of settlement events.
type BatchFlushFunc func(ctx context.Context, events []*BatchSettlementEvent) error

// RingBufferConfig configures the LedgerRingBuffer.
type RingBufferConfig struct {
	BufferSize    int           // e.g. 50,000
	BatchSize     int           // e.g. 200
	FlushInterval time.Duration // e.g. 100ms
	FlushHandler  BatchFlushFunc
}

// LedgerRingBuffer aggregates high-frequency LLM token micro-settlements and writes them in batches.
type LedgerRingBuffer struct {
	cfg        RingBufferConfig
	queue      chan *BatchSettlementEvent
	stopCh     chan struct{}
	doneCh     chan struct{}
	closeOnce  sync.Once
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewLedgerRingBuffer initializes an in-memory RingBuffer.
func NewLedgerRingBuffer(cfg RingBufferConfig) *LedgerRingBuffer {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 50000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 200
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}

	return &LedgerRingBuffer{
		cfg:    cfg,
		queue:  make(chan *BatchSettlementEvent, cfg.BufferSize),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Enqueue adds a settlement event to the buffer. Returns false if the queue is full.
func (rb *LedgerRingBuffer) Enqueue(event *BatchSettlementEvent) bool {
	if event == nil {
		return false
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	select {
	case rb.queue <- event:
		return true
	default:
		return false
	}
}

// Start launches the background flusher worker goroutine.
func (rb *LedgerRingBuffer) Start(parentCtx context.Context) {
	rb.ctx, rb.cancelFunc = context.WithCancel(parentCtx)

	go rb.workerLoop()
}

func (rb *LedgerRingBuffer) workerLoop() {
	defer close(rb.doneCh)

	ticker := time.NewTicker(rb.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]*BatchSettlementEvent, 0, rb.cfg.BatchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if rb.cfg.FlushHandler != nil {
			_ = rb.cfg.FlushHandler(rb.ctx, batch)
		}
		batch = make([]*BatchSettlementEvent, 0, rb.cfg.BatchSize)
	}

	for {
		select {
		case <-rb.stopCh:
			// Drain remaining elements
			for {
				select {
				case evt := <-rb.queue:
					batch = append(batch, evt)
					if len(batch) >= rb.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}

		case evt := <-rb.queue:
			batch = append(batch, evt)
			if len(batch) >= rb.cfg.BatchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// Close gracefully stops the worker, flushes all pending events, and terminates.
func (rb *LedgerRingBuffer) Close() error {
	var err error
	rb.closeOnce.Do(func() {
		close(rb.stopCh)
		<-rb.doneCh
		if rb.cancelFunc != nil {
			rb.cancelFunc()
		}
	})
	return err
}
