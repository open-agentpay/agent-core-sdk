/**
 * AgentPay Framework-Agnostic Integration Contracts and Types (Specification v0.1).
 */

export interface AgentContext {
  tenantId?: string;
  agentId?: string;
  runId?: string;
  framework?: string;
  frameworkVersion?: string;
  environment?: string;
  toolName?: string;
  taskId?: string;
  [key: string]: unknown;
}

export interface ResourceContext {
  resourceId?: string;
  challengeId?: string;
  [key: string]: unknown;
}

export interface PaymentRequest {
  resource: ResourceContext;
  idempotencyKey: string;
  context?: AgentContext;
  amount?: string;
  asset?: string;
  network?: string;
  metadata?: Record<string, unknown>;
}

export type DecisionType = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'REVIEW';

export interface PolicyDecision {
  decision: DecisionType | string;
  decisionId: string;
  reasonCode: string;
  reason?: string;
  paymentIntentId?: string;
  policyVersion?: string;
  budgetReservationId?: string;
  expiresAt?: string;
}

export type PaymentIntentStatus =
  | 'CREATED'
  | 'CHALLENGED'
  | 'AUTHORIZED'
  | 'VERIFIED'
  | 'COMPLETED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'FAILED'
  | 'CANCELLED'
  | 'NEEDS_REVIEW';

export type SettlementStatus =
  | 'NOT_STARTED'
  | 'HELD'
  | 'SUBMITTED'
  | 'PENDING'
  | 'CONFIRMED'
  | 'RELEASED'
  | 'FAILED'
  | 'REORGED'
  | 'UNKNOWN';

export type FulfillmentStatus =
  | 'NOT_STARTED'
  | 'PROCESSING'
  | 'DELIVERED'
  | 'FAILED'
  | 'RECOVERY_REQUIRED';

export interface PaymentResult {
  paymentIntentId: string;
  decision: string;
  paymentStatus: PaymentIntentStatus | string;
  settlementStatus: SettlementStatus | string;
  fulfillmentStatus: FulfillmentStatus | string;
  amount: string;
  asset: string;
  idempotencyKey: string;
  network?: string;
  transactionHash?: string;
  nextAction?: string;
}

export class AgentPayIntegrationError extends Error {
  readonly code: string;
  readonly statusCode: number;
  readonly nextAction: string;
  readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, statusCode = 400, nextAction = 'STOP', details?: Record<string, unknown>) {
    super(`[${code}] ${message}`);
    this.name = 'AgentPayIntegrationError';
    this.code = code;
    this.statusCode = statusCode;
    this.nextAction = nextAction;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayAuthenticationError extends AgentPayIntegrationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('UNAUTHENTICATED', message, 401, 'PROVIDE_API_KEY', details);
    this.name = 'AgentPayAuthenticationError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayPolicyDeniedError extends AgentPayIntegrationError {
  constructor(message: string, code = 'POLICY_DENIED', nextAction = 'STOP', details?: Record<string, unknown>) {
    super(code, message, 403, nextAction, details);
    this.name = 'AgentPayPolicyDeniedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayBudgetExceededError extends AgentPayPolicyDeniedError {
  constructor(message: string, nextAction = 'INCREASE_BUDGET', details?: Record<string, unknown>) {
    super(message, 'BUDGET_EXCEEDED', nextAction, details);
    this.name = 'AgentPayBudgetExceededError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayIdempotencyConflictError extends AgentPayIntegrationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('IDEMPOTENCY_CONFLICT', message, 409, 'POLL_STATUS', details);
    this.name = 'AgentPayIdempotencyConflictError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayRateLimitedError extends AgentPayIntegrationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('RATE_LIMITED', message, 429, 'BACKOFF', details);
    this.name = 'AgentPayRateLimitedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayCircuitOpenError extends AgentPayIntegrationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('CIRCUIT_OPEN', message, 503, 'STOP', details);
    this.name = 'AgentPayCircuitOpenError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AgentPayMerchantNotAllowedError extends AgentPayPolicyDeniedError {
  constructor(message: string, nextAction = 'STOP', details?: Record<string, unknown>) {
    super(message, 'MERCHANT_NOT_ALLOWED', nextAction, details);
    this.name = 'AgentPayMerchantNotAllowedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function mapIntegrationError(
  statusCode: number,
  code: string,
  message: string,
  nextAction = 'STOP',
  details?: Record<string, unknown>,
): AgentPayIntegrationError {
  const normCode = (code || '').toUpperCase();
  if (statusCode === 401 || normCode === 'UNAUTHENTICATED') {
    return new AgentPayAuthenticationError(message, details);
  }
  if (normCode === 'BUDGET_EXCEEDED') {
    return new AgentPayBudgetExceededError(message, nextAction, details);
  }
  if (normCode === 'MERCHANT_NOT_ALLOWED') {
    return new AgentPayMerchantNotAllowedError(message, nextAction, details);
  }
  if (statusCode === 409 || normCode === 'IDEMPOTENCY_CONFLICT') {
    return new AgentPayIdempotencyConflictError(message, details);
  }
  if (statusCode === 429 || normCode === 'RATE_LIMITED') {
    return new AgentPayRateLimitedError(message, details);
  }
  if (normCode === 'CIRCUIT_OPEN') {
    return new AgentPayCircuitOpenError(message, details);
  }
  if (statusCode === 403 || normCode.includes('POLICY')) {
    return new AgentPayPolicyDeniedError(message, code, nextAction, details);
  }
  return new AgentPayIntegrationError(code || 'UNKNOWN_ERROR', message, statusCode, nextAction, details);
}
