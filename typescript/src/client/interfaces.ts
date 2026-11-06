/**
 * Signer interface protocols for AgentPay.
 */

import type { PaymentAuthorization, PaymentChallenge } from '../core/models.js';
import type { ReservationToken } from '../policy/models.js';

export interface SignAuthorizationOptions {
  nonce?: `0x${string}` | string;
  tokenName?: string;
  tokenVersion?: string;
}

/**
 * Protocol for signing agents and cryptographic keystores.
 * Enforces firewall reservation binding before signing.
 */
export interface ISigner {
  /**
   * The canonical lowercase EVM address of the signing wallet.
   */
  readonly address: `0x${string}`;

  /**
   * Sign an EIP-712/3009 transfer authorization for the given challenge.
   *
   * MUST verify that the reservation matches the challenge before signing.
   *
   * @param challenge The PaymentChallenge from the 402 PAYMENT-REQUIRED header.
   * @param reservation The Approved ReservationToken from the policy engine.
   * @param options Optional signing options (nonce, tokenName, tokenVersion).
   * @returns PaymentAuthorization populated with cryptographic signature.
   * @throws ReservationMismatchError If the reservation does not match the challenge.
   * @throws SignerError If cryptographic signing fails.
   */
  signPaymentAuthorization(
    challenge: PaymentChallenge,
    reservation: ReservationToken,
    options?: SignAuthorizationOptions,
  ): Promise<PaymentAuthorization>;
}
