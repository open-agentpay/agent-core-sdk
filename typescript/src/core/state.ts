/**
 * Core Multi-Dimensional State Enums and Entity Models for AgentPay.
 *
 * Defines the four orthogonal state objects adhering to specs/payment-state-machine-v2.md:
 *   1. PaymentIntentState  (Buyer request lifecycle)
 *   2. SettlementState     (Blockchain / clearing funds transfer)
 *   3. FulfillmentState    (Upstream API / resource payload delivery)
 *   4. BudgetLedgerState   (Buyer firewall local quota reservation)
 */

export enum PaymentIntentState {
  CREATED = 'CREATED',
  AUTHORIZED = 'AUTHORIZED',
  PROCESSING = 'PROCESSING',
  SIGNATURE_SENT = 'SIGNATURE_SENT',
  COMPLETED = 'COMPLETED',
  SUCCEEDED = 'SUCCEEDED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED',
  CANCELLED = 'CANCELLED',
  RECOVERY_HOLD = 'RECOVERY_HOLD',
}

export enum SettlementState {
  NOT_STARTED = 'NOT_STARTED',
  NOT_SUBMITTED = 'NOT_SUBMITTED',
  SUBMITTED = 'SUBMITTED',
  PENDING = 'PENDING',
  CONFIRMED = 'CONFIRMED',
  SUCCESS = 'SUCCESS',
  FAILED = 'FAILED',
  REORGED = 'REORGED',
  UNKNOWN = 'UNKNOWN',
}

export enum FulfillmentState {
  NOT_STARTED = 'NOT_STARTED',
  NOT_DELIVERED = 'NOT_DELIVERED',
  PROCESSING = 'PROCESSING',
  DELIVERING = 'DELIVERING',
  DELIVERED = 'DELIVERED',
  FAILED = 'FAILED',
  RECOVERY_REQUIRED = 'RECOVERY_REQUIRED',
}

export enum BudgetLedgerState {
  RESERVED = 'RESERVED',
  COMMITTED = 'COMMITTED',
  RELEASED = 'RELEASED',
}

export interface BuyerIntentRecordInput {
  intentId: string;
  policyId: string;
  idempotencyKey: string;
  payerAddress: string;
  payeeAddress: string;
  assetAddress: string;
  networkId: string;
  amountBaseUnits: bigint | number;
  status?: PaymentIntentState;
  nonce?: string | null;
  validAfter?: number | null;
  validBefore?: number | null;
  rawSignature?: string | null;
  createdAt?: number;
  updatedAt?: number;
}

export class BuyerIntentRecord {
  readonly intentId: string;
  readonly policyId: string;
  readonly idempotencyKey: string;
  readonly payerAddress: string;
  readonly payeeAddress: string;
  readonly assetAddress: string;
  readonly networkId: string;
  readonly amountBaseUnits: bigint;
  readonly status: PaymentIntentState;
  readonly nonce: string | null;
  readonly validAfter: number | null;
  readonly validBefore: number | null;
  readonly rawSignature: string | null;
  readonly createdAt: number;
  readonly updatedAt: number;

  constructor(data: BuyerIntentRecordInput) {
    this.intentId = data.intentId;
    this.policyId = data.policyId;
    this.idempotencyKey = data.idempotencyKey;
    this.payerAddress = data.payerAddress.toLowerCase();
    this.payeeAddress = data.payeeAddress.toLowerCase();
    this.assetAddress = data.assetAddress.toLowerCase();
    this.networkId = data.networkId;
    this.amountBaseUnits =
      typeof data.amountBaseUnits === 'bigint' ? data.amountBaseUnits : BigInt(data.amountBaseUnits);
    this.status = data.status ?? PaymentIntentState.CREATED;
    this.nonce = data.nonce ?? null;
    this.validAfter = data.validAfter ?? null;
    this.validBefore = data.validBefore ?? null;
    this.rawSignature = data.rawSignature ?? null;
    this.createdAt = data.createdAt ?? 0;
    this.updatedAt = data.updatedAt ?? 0;
    Object.freeze(this);
  }
}
