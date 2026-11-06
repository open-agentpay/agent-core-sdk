package idempotency

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestIdempotencyLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(1 * time.Hour)

	tenantID := "ten_test_001"
	idemKey := "key_unique_123"
	hashA := ComputeRequestHash("POST", "/v1/chat", "", []byte(`{"prompt":"hello"}`))
	hashB := ComputeRequestHash("POST", "/v1/chat", "", []byte(`{"prompt":"different"}`))

	// 1. Initial request acquires lock (ResultNew)
	rec, result, err := store.CheckOrLock(ctx, tenantID, idemKey, hashA, "pi_001", "wallet")
	if err != nil {
		t.Fatalf("unexpected error on CheckOrLock: %v", err)
	}
	if result != ResultNew {
		t.Fatalf("expected ResultNew, got %v", result)
	}
	if rec.State != StateInProgress {
		t.Fatalf("expected state in_progress, got %s", rec.State)
	}

	// 2. Concurrent request with exact same key and hash while in progress -> ResultConflict
	_, result2, err := store.CheckOrLock(ctx, tenantID, idemKey, hashA, "pi_002", "wallet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2 != ResultConflict {
		t.Fatalf("expected ResultConflict for concurrent request, got %v", result2)
	}

	// 3. Request with same key but different hash -> ResultConflict
	_, result3, err := store.CheckOrLock(ctx, tenantID, idemKey, hashB, "pi_003", "wallet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result3 != ResultConflict {
		t.Fatalf("expected ResultConflict for tampered hash, got %v", result3)
	}

	// 4. Mark completed with response cache
	headers := map[string]string{"Content-Type": "application/json"}
	body := []byte(`{"result":"ok"}`)
	err = store.MarkCompleted(ctx, tenantID, idemKey, 200, headers, body)
	if err != nil {
		t.Fatalf("unexpected error on MarkCompleted: %v", err)
	}

	// 5. Subsequent request with same key and hash -> ResultCacheHit
	cachedRec, result4, err := store.CheckOrLock(ctx, tenantID, idemKey, hashA, "pi_004", "wallet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result4 != ResultCacheHit {
		t.Fatalf("expected ResultCacheHit, got %v", result4)
	}
	if cachedRec.StatusCode != 200 || string(cachedRec.ResponseBody) != `{"result":"ok"}` {
		t.Fatalf("cached record mismatch: status=%d body=%s", cachedRec.StatusCode, string(cachedRec.ResponseBody))
	}
}

func TestIdempotencyFreeReplayAfterUpstreamFailure(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(1 * time.Hour)

	tenantID := "ten_recovery_002"
	idemKey := "key_recovery_456"
	hash := ComputeRequestHash("POST", "/v1/models", "", []byte(`{"input":"test"}`))

	// Step 1: Initial call locks
	_, res1, err := store.CheckOrLock(ctx, tenantID, idemKey, hash, "pi_rec_1", "wallet")
	if err != nil || res1 != ResultNew {
		t.Fatalf("expected ResultNew, got %v (err: %v)", res1, err)
	}

	// Step 2: Attach Hold ID
	err = store.AttachPaymentDetails(ctx, tenantID, idemKey, "hld_9999", "")
	if err != nil {
		t.Fatalf("failed to attach hold: %v", err)
	}

	// Step 3: Upstream returns 504 Timeout -> Mark Recovery Required
	err = store.MarkRecoveryRequired(ctx, tenantID, idemKey, 504, "upstream timeout")
	if err != nil {
		t.Fatalf("failed to mark recovery: %v", err)
	}

	// Step 4: Client re-submits exact same request -> ResultFreeReplay!
	rec, res2, err := store.CheckOrLock(ctx, tenantID, idemKey, hash, "pi_rec_1_retry", "wallet")
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if res2 != ResultFreeReplay {
		t.Fatalf("expected ResultFreeReplay, got %v", res2)
	}
	if rec.HoldID != "hld_9999" {
		t.Fatalf("expected preserved hold hld_9999, got %s", rec.HoldID)
	}
	if rec.AttemptCount != 2 {
		t.Fatalf("expected attempt count 2, got %d", rec.AttemptCount)
	}

	// Step 5: Second attempt succeeds -> Mark Completed
	err = store.MarkCompleted(ctx, tenantID, idemKey, 200, nil, []byte(`{"status":"success"}`))
	if err != nil {
		t.Fatalf("failed to mark completed: %v", err)
	}

	// Step 6: Third attempt -> Cache Hit
	recFinal, res3, err := store.CheckOrLock(ctx, tenantID, idemKey, hash, "pi_rec_1_third", "wallet")
	if err != nil || res3 != ResultCacheHit {
		t.Fatalf("expected ResultCacheHit, got %v (err: %v)", res3, err)
	}
	if string(recFinal.ResponseBody) != `{"status":"success"}` {
		t.Fatalf("expected cached body, got %s", string(recFinal.ResponseBody))
	}
}

func TestIdempotencyConcurrentStress(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(1 * time.Hour)

	tenantID := "ten_stress_003"
	idemKey := "key_stress_789"
	hash := ComputeRequestHash("POST", "/v1/stress", "", []byte(`{"concurrency":100}`))

	const concurrency = 20
	var wg sync.WaitGroup
	results := make([]CheckResult, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, res, _ := store.CheckOrLock(ctx, tenantID, idemKey, hash, "pi_concurrent", "wallet")
			results[idx] = res
		}(i)
	}
	wg.Wait()

	newCount := 0
	conflictCount := 0
	for _, r := range results {
		if r == ResultNew {
			newCount++
		} else if r == ResultConflict {
			conflictCount++
		}
	}

	if newCount != 1 {
		t.Fatalf("expected exactly 1 ResultNew under concurrency, got %d", newCount)
	}
	if conflictCount != concurrency-1 {
		t.Fatalf("expected %d conflicts, got %d", concurrency-1, conflictCount)
	}
}
