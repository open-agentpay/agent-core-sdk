/**
 * State transition and coordination exceptions for AgentPay.
 *
 * Standardized error types for illegal lifecycle mutations and safety violations:
 *   - IllegalStateTransitionError
 *   - SignatureSentReleaseForbiddenError
 *   - OrphanedSettlementRollbackForbiddenError
 *   - InvalidCompositeStateError
 *   - IdempotencyLockConflictError
 */

export class StateCoordinationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StateCoordinationError';
  }
}

export class IllegalStateTransitionError extends StateCoordinationError {
  readonly entityType: string;
  readonly fromState: string;
  readonly toState: string;
  readonly detail: string;

  constructor(entityType: string, fromState: string, toState: string, detail = '') {
    const msg = detail
      ? `Illegal ${entityType} state transition from '${fromState}' to '${toState}': ${detail}`
      : `Illegal ${entityType} state transition from '${fromState}' to '${toState}'`;
    super(msg);
    this.name = 'IllegalStateTransitionError';
    this.entityType = entityType;
    this.fromState = fromState;
    this.toState = toState;
    this.detail = detail;
  }
}

export class SignatureSentReleaseForbiddenError extends StateCoordinationError {
  readonly intentId: string;
  readonly currentState: string;

  constructor(intentId: string, currentState: string) {
    super(
      `Cannot release or cancel intent '${intentId}' in state '${currentState}': ` +
        'Cryptographic signature has already been transmitted on the wire. ' +
        'Quota must remain RESERVED until reconciliation or successful retry.',
    );
    this.name = 'SignatureSentReleaseForbiddenError';
    this.intentId = intentId;
    this.currentState = currentState;
  }
}

export class OrphanedSettlementRollbackForbiddenError extends StateCoordinationError {
  readonly settlementId: string;
  readonly settlementState: string;

  constructor(settlementId: string, settlementState: string) {
    super(
      `Cannot void settlement '${settlementId}' in state '${settlementState}': ` +
        'Payment verification succeeded and funds transfer is active. ' +
        'Upstream fulfillment failures must not rollback settlement.',
    );
    this.name = 'OrphanedSettlementRollbackForbiddenError';
    this.settlementId = settlementId;
    this.settlementState = settlementState;
  }
}

export class InvalidCompositeStateError extends StateCoordinationError {
  readonly intentState: string;
  readonly settlementState: string;
  readonly fulfillmentState: string;
  readonly ledgerState: string | null;
  readonly reason: string;

  constructor(
    intentState: string,
    settlementState: string,
    fulfillmentState: string,
    ledgerState: string | null,
    reason: string,
  ) {
    super(
      `Invalid composite state (Intent=${intentState}, Settlement=${settlementState}, ` +
        `Fulfillment=${fulfillmentState}, Ledger=${ledgerState ?? 'null'}): ${reason}`,
    );
    this.name = 'InvalidCompositeStateError';
    this.intentState = intentState;
    this.settlementState = settlementState;
    this.fulfillmentState = fulfillmentState;
    this.ledgerState = ledgerState;
    this.reason = reason;
  }
}

export class IdempotencyLockConflictError extends StateCoordinationError {
  readonly payerAddress: string;
  readonly idempotencyKey: string;
  readonly lockedUntil: number;

  constructor(payerAddress: string, idempotencyKey: string, lockedUntil: number) {
    super(
      `Concurrent request in-flight for (${payerAddress}, ${idempotencyKey}). ` +
        `Lease locked until Unix timestamp ${lockedUntil}.`,
    );
    this.name = 'IdempotencyLockConflictError';
    this.payerAddress = payerAddress;
    this.idempotencyKey = idempotencyKey;
    this.lockedUntil = lockedUntil;
  }
}
