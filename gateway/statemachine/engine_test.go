package statemachine

import (
	"path/filepath"
	"runtime"
	"testing"
)

func getStateMachineSpecPath(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve current file path")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "specs", "conformance", "state-machine.json")
}

func TestStateMachineSpecIntegrityAndConformance(t *testing.T) {
	specPath := getStateMachineSpecPath(t)
	spec, err := LoadSpecificationFromFile(specPath)
	if err != nil {
		t.Fatalf("failed to load state machine spec: %v", err)
	}

	if spec.Version != "2.1.0" {
		t.Errorf("expected spec version 2.1.0, got %s", spec.Version)
	}

	expectedEntities := []string{"payment_intent", "settlement", "fulfillment"}
	for _, entity := range expectedEntities {
		if _, ok := spec.Entities[entity]; !ok {
			t.Errorf("missing entity '%s' in spec", entity)
		}
	}

	engine := NewEngine(*spec)

	// 1. All valid transitions from spec produce expected target state
	for entityName, entitySpec := range spec.Entities {
		for _, trans := range entitySpec.Transitions {
			t.Run(entityName+"_"+trans.From+"_"+trans.Event, func(t *testing.T) {
				target, err := engine.Transition(entityName, trans.From, trans.Event)
				if err != nil {
					t.Fatalf("unexpected transition error: %v", err)
				}
				if target != trans.To {
					t.Errorf("expected target %s, got %s", trans.To, target)
				}
			})
		}
	}

	// 2. Strict Rejection: terminal states reject subsequent state mutations
	t.Run("TerminalStateImmutability", func(t *testing.T) {
		terminalCases := []struct {
			entity string
			state  string
			event  string
		}{
			{"settlement", "confirmed", "fail"},
			{"settlement", "confirmed", "submit"},
			{"settlement", "failed", "confirm"},
			{"settlement", "released", "capture"},
			{"fulfillment", "succeeded", "retry"},
			{"fulfillment", "failed", "succeed"},
			{"payment_intent", "settled", "expire"},
			{"payment_intent", "failed", "activate"},
		}

		for _, tc := range terminalCases {
			_, err := engine.Transition(tc.entity, tc.state, tc.event)
			if err == nil {
				t.Errorf("expected error processing event %s on terminal state %s for entity %s, got nil", tc.event, tc.state, tc.entity)
			}
		}
	})

	// 3. Strict Rejection: illegal/unregistered transitions are rejected
	t.Run("IllegalTransitionsRejected", func(t *testing.T) {
		illegalCases := []struct {
			entity string
			state  string
			event  string
		}{
			{"settlement", "not_started", "confirm"},
			{"settlement", "submitted", "release"},
			{"fulfillment", "pending", "succeed"}, // requires dispatch first
			{"payment_intent", "requires_payment", "settle"},
		}

		for _, tc := range illegalCases {
			_, err := engine.Transition(tc.entity, tc.state, tc.event)
			if err == nil {
				t.Errorf("expected error for illegal transition (%s, %s, %s), got nil", tc.entity, tc.state, tc.event)
			}
		}
	})

	// 4. Invariant: INV_1_DISPATCH_GUARD
	t.Run("DispatchGuardInvariant", func(t *testing.T) {
		// Onchain path requires settlement == confirmed
		if engine.CanDispatchFulfillment("submitted", "onchain") {
			t.Errorf("onchain dispatch must be blocked when settlement is submitted")
		}
		if engine.CanDispatchFulfillment("held", "onchain") {
			t.Errorf("onchain dispatch must be blocked when settlement is held")
		}
		if !engine.CanDispatchFulfillment("confirmed", "onchain") {
			t.Errorf("onchain dispatch must succeed when settlement is confirmed")
		}

		// onchain_sync requires settlement == confirmed
		if engine.CanDispatchFulfillment("submitted", "onchain_sync") {
			t.Errorf("onchain_sync dispatch must be blocked when settlement is submitted")
		}
		if !engine.CanDispatchFulfillment("confirmed", "onchain_sync") {
			t.Errorf("onchain_sync dispatch must succeed when settlement is confirmed")
		}

		// onchain_async allows dispatch with submitted (signature verified & nonce persisted)
		if !engine.CanDispatchFulfillment("submitted", "onchain_async") {
			t.Errorf("onchain_async dispatch should be allowed when settlement is submitted")
		}
		if !engine.CanDispatchFulfillment("confirmed", "onchain_async") {
			t.Errorf("onchain_async dispatch should be allowed when settlement is confirmed")
		}

		// Wallet path requires settlement == held
		if engine.CanDispatchFulfillment("not_started", "wallet") {
			t.Errorf("wallet dispatch must be blocked when settlement is not_started")
		}
		if !engine.CanDispatchFulfillment("held", "wallet") {
			t.Errorf("wallet dispatch must succeed when settlement is held")
		}
		if engine.CanDispatchFulfillment("confirmed", "wallet") {
			t.Errorf("wallet dispatch must be blocked when settlement is confirmed (capture happens after fulfillment)")
		}
	})

	// 5. Invariant: INV_2_UNKNOWN_SUBMIT_GUARD
	t.Run("UnknownSubmitGuardInvariant", func(t *testing.T) {
		if !engine.CanSubmitSettlement("not_started") {
			t.Errorf("submission should be allowed from not_started")
		}
		if engine.CanSubmitSettlement("unknown") {
			t.Errorf("INV_2 violation: submission MUST NOT be allowed when settlement is unknown")
		}
		if engine.CanSubmitSettlement("submitted") {
			t.Errorf("INV_2 violation: submission MUST NOT be allowed when settlement is submitted")
		}
	})

	// 6. Upstream 5xx Guard: Upstream 5xx/timeout transitions Fulfillment to unknown, never directly failed
	t.Run("Upstream5xxFulfillmentGuard", func(t *testing.T) {
		// fulfillment in progress + upstream_timeout -> unknown
		targetStateTimeout, err := engine.Transition("fulfillment", "in_progress", "upstream_timeout")
		if err != nil {
			t.Fatalf("unexpected error on upstream_timeout: %v", err)
		}
		if targetStateTimeout != "unknown" {
			t.Errorf("expected fulfillment on upstream_timeout to transition to unknown, got %s", targetStateTimeout)
		}

		// fulfillment in progress + upstream_5xx -> unknown
		targetState5xx, err := engine.Transition("fulfillment", "in_progress", "upstream_5xx")
		if err != nil {
			t.Fatalf("unexpected error on upstream_5xx: %v", err)
		}
		if targetState5xx != "unknown" {
			t.Errorf("expected fulfillment on upstream_5xx to transition to unknown, got %s", targetState5xx)
		}

		// fulfillment in progress + upstream_4xx -> failed (explicit non-execution client error)
		targetState4xx, err := engine.Transition("fulfillment", "in_progress", "upstream_4xx")
		if err != nil {
			t.Fatalf("unexpected error on upstream_4xx: %v", err)
		}
		if targetState4xx != "failed" {
			t.Errorf("expected fulfillment on upstream_4xx to transition to failed, got %s", targetState4xx)
		}
	})

	// 7. Wallet Hold Lifecycle
	t.Run("WalletHoldTransitions", func(t *testing.T) {
		// not_started -> hold_acquired -> held
		s1, err := engine.Transition("settlement", "not_started", "hold_acquired")
		if err != nil || s1 != "held" {
			t.Errorf("expected not_started+hold_acquired -> held, got %s, err: %v", s1, err)
		}

		// held -> capture -> confirmed
		s2, err := engine.Transition("settlement", s1, "capture")
		if err != nil || s2 != "confirmed" {
			t.Errorf("expected held+capture -> confirmed, got %s, err: %v", s2, err)
		}

		// held -> release -> released
		s3, err := engine.Transition("settlement", "held", "release")
		if err != nil || s3 != "released" {
			t.Errorf("expected held+release -> released, got %s, err: %v", s3, err)
		}
	})

	// 8. Composite Views Derivation: Exactly identical to Python test_state_machine_matrix.py
	t.Run("CompositeViewDerivations", func(t *testing.T) {
		testCases := []struct {
			settlement  string
			fulfillment string
			expected    string
		}{
			{"held", "not_started", "WALLET_HOLD_PROCESSING"},
			{"pending", "not_started", "SETTLEMENT_IN_PROGRESS"},
			{"unknown", "not_started", "SETTLEMENT_IN_PROGRESS"},
			{"confirmed", "in_progress", "FULFILLMENT_IN_PROGRESS"},
			{"confirmed", "succeeded", "COMPLETED"},
			{"confirmed", "failed", "SETTLED_FULFILLMENT_FAILED_REFUND_REQUIRED"},
			{"confirmed", "unknown", "SETTLED_FULFILLMENT_UNKNOWN_NEEDS_REVIEW"},
			{"released", "failed", "RELEASED_UNBILLED"},
			{"failed", "not_started", "PAYMENT_FAILED"},
		}

		for _, tc := range testCases {
			disp := engine.DeriveCompositeView(tc.settlement, tc.fulfillment)
			if disp != tc.expected {
				t.Errorf("composite view mismatch for (%s, %s): expected %s, got %s", tc.settlement, tc.fulfillment, tc.expected, disp)
			}
		}
	})
}
