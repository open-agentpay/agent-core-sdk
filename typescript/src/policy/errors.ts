/**
 * Standardized policy engine error codes and exception types.
 *
 * All error codes are defined in policy-engine-spec.md §2 and are language-agnostic
 * uppercase string constants.
 */

export enum PolicyErrorCode {
  // 1. Administrative lock
  POLICY_FROZEN = 'POLICY_FROZEN',

  // 2. Circuit breaker
  CIRCUIT_BREAKER_OPEN = 'CIRCUIT_BREAKER_OPEN',

  // 3. Request format validation
  INVALID_AMOUNT_FORMAT = 'INVALID_AMOUNT_FORMAT',
  INVALID_REQUEST = 'INVALID_REQUEST',

  // 4. Whitelist matrix (evaluated in order: network → asset → payee → domain)
  NETWORK_NOT_WHITELISTED = 'NETWORK_NOT_WHITELISTED',
  ASSET_NOT_WHITELISTED = 'ASSET_NOT_WHITELISTED',
  PAYEE_NOT_WHITELISTED = 'PAYEE_NOT_WHITELISTED',
  DOMAIN_NOT_WHITELISTED = 'DOMAIN_NOT_WHITELISTED',

  // 5. Single-transaction cap
  SINGLE_TX_CAP_EXCEEDED = 'SINGLE_TX_CAP_EXCEEDED',

  // 6. Lifetime budget
  LIFETIME_BUDGET_EXCEEDED = 'LIFETIME_BUDGET_EXCEEDED',

  // 7. Rolling 24h budget
  DAILY_BUDGET_EXCEEDED = 'DAILY_BUDGET_EXCEEDED',

  // Reservation lifecycle & system errors
  RESERVATION_EXPIRED = 'RESERVATION_EXPIRED',
  RESERVATION_ALREADY_FINALIZED = 'RESERVATION_ALREADY_FINALIZED',
  UNMETERED_CREDENTIAL = 'UNMETERED_CREDENTIAL',
  DUPLICATE_INTENT = 'DUPLICATE_INTENT',
  POLICY_SYSTEM_ERROR = 'POLICY_SYSTEM_ERROR',
}

export class PolicyViolationError extends Error {
  readonly code: PolicyErrorCode;
  readonly detail: string;

  constructor(code: PolicyErrorCode, detail = '') {
    const message = detail ? `${code}: ${detail}` : code;
    super(message);
    this.name = 'PolicyViolationError';
    this.code = code;
    this.detail = detail;
  }

  override toString(): string {
    return `PolicyViolationError(code=${this.code}, detail=${JSON.stringify(this.detail)})`;
  }
}
