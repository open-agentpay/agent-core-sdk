/**
 * State Transition Guards and Multi-Entity Validation Rules for AgentPay.
 *
 * Enforces:
 *   - Transition guard matrices for Intent, Settlement, Fulfillment, and Ledger
 *   - Strict Anti-Overspend invariant: SIGNATURE_SENT/RECOVERY_HOLD cannot release
 *   - Strict Anti-Rollback invariant: Upstream 5xx cannot void Settlement
 *   - Legal composite state whitelist
 */

import {
  BudgetLedgerState,
  FulfillmentState,
  PaymentIntentState,
  SettlementState,
} from '../core/state.js';
import {
  IllegalStateTransitionError,
  InvalidCompositeStateError,
  OrphanedSettlementRollbackForbiddenError,
  SignatureSentReleaseForbiddenError,
} from './errors.js';

// ---------------------------------------------------------------------------
// 1. Individual Entity Transition Matrices
// ---------------------------------------------------------------------------

export const LEGAL_INTENT_TRANSITIONS: Readonly<Record<PaymentIntentState, ReadonlySet<PaymentIntentState>>> = Object.freeze({
  [PaymentIntentState.CREATED]: new Set([
    PaymentIntentState.PROCESSING,
    PaymentIntentState.AUTHORIZED,
    PaymentIntentState.REJECTED,
    PaymentIntentState.EXPIRED,
    PaymentIntentState.CANCELLED,
  ]),
  [PaymentIntentState.AUTHORIZED]: new Set([
    PaymentIntentState.PROCESSING,
    PaymentIntentState.SIGNATURE_SENT,
    PaymentIntentState.CANCELLED,
  ]),
  [PaymentIntentState.PROCESSING]: new Set([
    PaymentIntentState.SIGNATURE_SENT,
    PaymentIntentState.SUCCEEDED,
    PaymentIntentState.COMPLETED,
    PaymentIntentState.RECOVERY_HOLD,
    PaymentIntentState.CANCELLED,
  ]),
  [PaymentIntentState.SIGNATURE_SENT]: new Set([
    PaymentIntentState.SUCCEEDED,
    PaymentIntentState.COMPLETED,
    PaymentIntentState.RECOVERY_HOLD,
  ]),
  [PaymentIntentState.RECOVERY_HOLD]: new Set([
    PaymentIntentState.SUCCEEDED,
    PaymentIntentState.COMPLETED,
    PaymentIntentState.REJECTED, // Permitted ONLY after reconciler proves nonce unspent
  ]),
  // Terminal states
  [PaymentIntentState.COMPLETED]: new Set<PaymentIntentState>(),
  [PaymentIntentState.SUCCEEDED]: new Set<PaymentIntentState>(),
  [PaymentIntentState.REJECTED]: new Set<PaymentIntentState>(),
  [PaymentIntentState.EXPIRED]: new Set<PaymentIntentState>(),
  [PaymentIntentState.CANCELLED]: new Set<PaymentIntentState>(),
});

export const LEGAL_SETTLEMENT_TRANSITIONS: Readonly<Record<SettlementState, ReadonlySet<SettlementState>>> = Object.freeze({
  [SettlementState.NOT_STARTED]: new Set([
    SettlementState.SUBMITTED,
    SettlementState.PENDING,
    SettlementState.FAILED,
  ]),
  [SettlementState.NOT_SUBMITTED]: new Set([
    SettlementState.SUBMITTED,
    SettlementState.PENDING,
    SettlementState.FAILED,
  ]),
  [SettlementState.SUBMITTED]: new Set([
    SettlementState.PENDING,
    SettlementState.CONFIRMED,
    SettlementState.SUCCESS,
    SettlementState.FAILED,
    SettlementState.UNKNOWN,
  ]),
  [SettlementState.PENDING]: new Set([
    SettlementState.CONFIRMED,
    SettlementState.SUCCESS,
    SettlementState.FAILED,
    SettlementState.REORGED,
    SettlementState.UNKNOWN,
  ]),
  [SettlementState.REORGED]: new Set([
    SettlementState.SUBMITTED,
    SettlementState.FAILED,
  ]),
  [SettlementState.UNKNOWN]: new Set([
    SettlementState.CONFIRMED,
    SettlementState.SUCCESS,
    SettlementState.PENDING,
    SettlementState.FAILED,
  ]),
  // Terminal states
  [SettlementState.CONFIRMED]: new Set<SettlementState>(),
  [SettlementState.SUCCESS]: new Set<SettlementState>(),
  [SettlementState.FAILED]: new Set<SettlementState>(),
});

export const LEGAL_FULFILLMENT_TRANSITIONS: Readonly<Record<FulfillmentState, ReadonlySet<FulfillmentState>>> = Object.freeze({
  [FulfillmentState.NOT_STARTED]: new Set([
    FulfillmentState.PROCESSING,
    FulfillmentState.DELIVERING,
    FulfillmentState.FAILED,
  ]),
  [FulfillmentState.NOT_DELIVERED]: new Set([
    FulfillmentState.PROCESSING,
    FulfillmentState.DELIVERING,
    FulfillmentState.FAILED,
  ]),
  [FulfillmentState.PROCESSING]: new Set([
    FulfillmentState.DELIVERED,
    FulfillmentState.FAILED,
    FulfillmentState.RECOVERY_REQUIRED,
  ]),
  [FulfillmentState.DELIVERING]: new Set([
    FulfillmentState.DELIVERED,
    FulfillmentState.FAILED,
    FulfillmentState.RECOVERY_REQUIRED,
  ]),
  [FulfillmentState.RECOVERY_REQUIRED]: new Set([
    FulfillmentState.PROCESSING,
    FulfillmentState.DELIVERING,
    FulfillmentState.DELIVERED,
    FulfillmentState.FAILED,
  ]),
  // Terminal states
  [FulfillmentState.DELIVERED]: new Set<FulfillmentState>(),
  [FulfillmentState.FAILED]: new Set<FulfillmentState>(),
});

export const LEGAL_LEDGER_TRANSITIONS: Readonly<Record<BudgetLedgerState, ReadonlySet<BudgetLedgerState>>> = Object.freeze({
  [BudgetLedgerState.RESERVED]: new Set([
    BudgetLedgerState.COMMITTED,
    BudgetLedgerState.RELEASED,
  ]),
  // Terminal states
  [BudgetLedgerState.COMMITTED]: new Set<BudgetLedgerState>(),
  [BudgetLedgerState.RELEASED]: new Set<BudgetLedgerState>(),
});

// ---------------------------------------------------------------------------
// 2. Guard Functions
// ---------------------------------------------------------------------------

export function validateIntentTransition(
  fromState: PaymentIntentState,
  toState: PaymentIntentState,
  options?: { intentId?: string },
): void {
  if (fromState === toState) {
    return;
  }

  // Guardrail: Once SIGNATURE_SENT or RECOVERY_HOLD, never transition to CANCELLED
  if (
    (fromState === PaymentIntentState.SIGNATURE_SENT || fromState === PaymentIntentState.RECOVERY_HOLD) &&
    toState === PaymentIntentState.CANCELLED
  ) {
    throw new SignatureSentReleaseForbiddenError(options?.intentId ?? '', fromState);
  }

  const allowed = LEGAL_INTENT_TRANSITIONS[fromState] || new Set();
  if (!allowed.has(toState)) {
    throw new IllegalStateTransitionError(
      'PaymentIntent',
      fromState,
      toState,
      `Allowed transitions from '${fromState}': ${Array.from(allowed).join(', ')}`,
    );
  }
}

export function validateSettlementTransition(
  fromState: SettlementState,
  toState: SettlementState,
  options?: { settlementId?: string },
): void {
  if (fromState === toState) {
    return;
  }

  // Guardrail: Active settlements cannot be reset to NOT_STARTED / NOT_SUBMITTED
  if (
    (fromState === SettlementState.SUBMITTED ||
      fromState === SettlementState.PENDING ||
      fromState === SettlementState.CONFIRMED ||
      fromState === SettlementState.SUCCESS) &&
    (toState === SettlementState.NOT_STARTED || toState === SettlementState.NOT_SUBMITTED)
  ) {
    throw new OrphanedSettlementRollbackForbiddenError(options?.settlementId ?? '', fromState);
  }

  const allowed = LEGAL_SETTLEMENT_TRANSITIONS[fromState] || new Set();
  if (!allowed.has(toState)) {
    throw new IllegalStateTransitionError(
      'Settlement',
      fromState,
      toState,
      `Allowed transitions from '${fromState}': ${Array.from(allowed).join(', ')}`,
    );
  }
}

export function validateFulfillmentTransition(
  fromState: FulfillmentState,
  toState: FulfillmentState,
): void {
  if (fromState === toState) {
    return;
  }

  const allowed = LEGAL_FULFILLMENT_TRANSITIONS[fromState] || new Set();
  if (!allowed.has(toState)) {
    throw new IllegalStateTransitionError(
      'Fulfillment',
      fromState,
      toState,
      `Allowed transitions from '${fromState}': ${Array.from(allowed).join(', ')}`,
    );
  }
}

export function validateLedgerTransition(
  fromState: BudgetLedgerState,
  toState: BudgetLedgerState,
): void {
  if (fromState === toState) {
    return;
  }

  const allowed = LEGAL_LEDGER_TRANSITIONS[fromState] || new Set();
  if (!allowed.has(toState)) {
    throw new IllegalStateTransitionError(
      'BudgetLedger',
      fromState,
      toState,
      `Ledger entry is already finalized in '${fromState}'.`,
    );
  }
}

// ---------------------------------------------------------------------------
// 3. Composite State Whitelist Validation
// ---------------------------------------------------------------------------

export function validateCompositeState(
  intentState: PaymentIntentState,
  settlementState: SettlementState,
  fulfillmentState: FulfillmentState,
  ledgerState?: BudgetLedgerState | null,
): void {
  // Invariant 1: Anti-Overspend Rule
  if (
    (intentState === PaymentIntentState.SIGNATURE_SENT || intentState === PaymentIntentState.RECOVERY_HOLD) &&
    ledgerState === BudgetLedgerState.RELEASED
  ) {
    throw new InvalidCompositeStateError(
      intentState,
      settlementState,
      fulfillmentState,
      ledgerState ?? null,
      'Anti-Overspend Violation: Budget cannot be RELEASED while intent is in-flight or held.',
    );
  }

  // Invariant 2: Success Alignment Rule
  if (intentState === PaymentIntentState.SUCCEEDED || intentState === PaymentIntentState.COMPLETED) {
    if (fulfillmentState !== FulfillmentState.DELIVERED) {
      throw new InvalidCompositeStateError(
        intentState,
        settlementState,
        fulfillmentState,
        ledgerState ?? null,
        'Intent cannot be SUCCEEDED if resource was not DELIVERED.',
      );
    }
    if (ledgerState !== undefined && ledgerState !== null && ledgerState !== BudgetLedgerState.COMMITTED) {
      throw new InvalidCompositeStateError(
        intentState,
        settlementState,
        fulfillmentState,
        ledgerState,
        'Intent cannot be SUCCEEDED unless budget quota is COMMITTED.',
      );
    }
  }

  // Invariant 3: Delivered Resource Settlement Requirement
  if (
    fulfillmentState === FulfillmentState.DELIVERED &&
    settlementState !== SettlementState.SUBMITTED &&
    settlementState !== SettlementState.PENDING &&
    settlementState !== SettlementState.CONFIRMED &&
    settlementState !== SettlementState.SUCCESS
  ) {
    throw new InvalidCompositeStateError(
      intentState,
      settlementState,
      fulfillmentState,
      ledgerState ?? null,
      'Fulfillment cannot be DELIVERED if settlement was never submitted or succeeded.',
    );
  }
}
