package agent

import (
	"context"
	"errors"
	"testing"
)

func TestPolicyEvaluatorInterfaceAndChain(t *testing.T) {
	ctx := context.Background()

	// 1. Single evaluator via EvaluatorFunc
	evaluator1 := EvaluatorFunc(func(ctx context.Context, req *PolicyRequest) PolicyDecision {
		if req.AmountBase > 1000 {
			return PolicyDecision{Allowed: false, ReasonCode: "ERR_CUSTOM_CAP", Reason: "Custom limit exceeded"}
		}
		return PolicyDecision{Allowed: true, ReasonCode: CodeAllow}
	})

	reqLow := &PolicyRequest{AmountBase: 500}
	decLow := evaluator1.EvaluatePolicy(ctx, reqLow)
	if !decLow.Allowed {
		t.Fatalf("Expected low amount to be allowed, got: %+v", decLow)
	}

	reqHigh := &PolicyRequest{AmountBase: 1500}
	decHigh := evaluator1.EvaluatePolicy(ctx, reqHigh)
	if decHigh.Allowed || decHigh.ReasonCode != "ERR_CUSTOM_CAP" {
		t.Fatalf("Expected high amount to be rejected, got: %+v", decHigh)
	}

	// 2. ChainEvaluator: halts on first rejection
	evaluator2 := EvaluatorFunc(func(ctx context.Context, req *PolicyRequest) PolicyDecision {
		if req.Currency != "CNY" {
			return PolicyDecision{Allowed: false, ReasonCode: "ERR_UNSUPPORTED_CURRENCY"}
		}
		return PolicyDecision{Allowed: true, ReasonCode: CodeAllow}
	})

	chain := ChainEvaluator{evaluator1, evaluator2}

	// Pass both
	passReq := &PolicyRequest{AmountBase: 500, Currency: "CNY"}
	if dec := chain.EvaluatePolicy(ctx, passReq); !dec.Allowed {
		t.Fatalf("Expected pass, got: %+v", dec)
	}

	// Fail on second evaluator
	currFailReq := &PolicyRequest{AmountBase: 500, Currency: "USD"}
	if dec := chain.EvaluatePolicy(ctx, currFailReq); dec.Allowed || dec.ReasonCode != "ERR_UNSUPPORTED_CURRENCY" {
		t.Fatalf("Expected ERR_UNSUPPORTED_CURRENCY, got: %+v", dec)
	}
}

type mockSpendRecorder struct {
	records []*SpendRecord
}

func (m *mockSpendRecorder) RecordSpend(ctx context.Context, record *SpendRecord) error {
	if record == nil {
		return errors.New("nil record")
	}
	m.records = append(m.records, record)
	return nil
}

func TestSpendRecorderInterface(t *testing.T) {
	ctx := context.Background()
	rec := &mockSpendRecorder{}

	err := rec.RecordSpend(ctx, &SpendRecord{
		TenantID:   "ten_01",
		ProjectID:  "prj_01",
		AgentID:    "agt_01",
		AmountBase: 500000,
	})
	if err != nil {
		t.Fatalf("RecordSpend failed: %v", err)
	}
	if len(rec.records) != 1 || rec.records[0].AmountBase != 500000 {
		t.Fatalf("Unexpected recorded state: %+v", rec.records)
	}
}
