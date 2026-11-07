/**
 * Signer interface protocols for AgentPay.
 */

import type { PaymentAuthorization, PaymentChallenge } from '../core/models.js';
import type { ReservationToken } from '../policy/models.js';

export interface SignAuthorizationOptions {
  nonce?: string;
  tokenName?: string;
  tokenVersion?: string;
}

/**
 * Protocol for signing agents and cryptographic keystores.
 * Enforces firewall reservation binding before signing.
 */
export interface ISigner {
  /**
   * The canonical address or identity of the signing wallet.
   */
  readonly address: string;

  /**
   * Sign a payment authorization for the given challenge.
   *
   * MUST verify that the reservation matches the challenge before signing.
   *
   * @param challenge The PaymentChallenge from the 402 PAYMENT-REQUIRED header.
   * @param reservation The Approved ReservationToken from the policy engine.
   * @param options Optional signing options (nonce, tokenName, tokenVersion).
   * @returns PaymentAuthorization populated with signature.
   * @throws ReservationMismatchError If the reservation does not match the challenge.
   * @throws SignerError If cryptographic signing fails.
   */
  signPaymentAuthorization(
    challenge: PaymentChallenge,
    reservation: ReservationToken,
    options?: SignAuthorizationOptions,
  ): Promise<PaymentAuthorization>;
}
