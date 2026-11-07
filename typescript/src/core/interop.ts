/**
 * x402 Upstream Interoperability Module.
 *
 * Provides adapter functions between AgentPay native models and external plain object/x402 representations.
 */

import { PaymentAuthorization, PaymentChallenge } from './models.js';

export function toOfficialChallenge(challenge: PaymentChallenge): Record<string, unknown> {
  return challenge.toJSON();
}

export function fromOfficialChallenge(obj: unknown): PaymentChallenge {
  if (obj instanceof PaymentChallenge) {
    return obj;
  }
  if (obj && typeof obj === 'object') {
    return PaymentChallenge.modelValidate(obj);
  }
  throw new TypeError(`Cannot convert object of type ${typeof obj} to PaymentChallenge`);
}

export function fromOfficialAuthorization(obj: unknown): PaymentAuthorization {
  if (obj instanceof PaymentAuthorization) {
    return obj;
  }
  if (obj && typeof obj === 'object') {
    return PaymentAuthorization.modelValidate(obj);
  }
  throw new TypeError(`Cannot convert object of type ${typeof obj} to PaymentAuthorization`);
}
