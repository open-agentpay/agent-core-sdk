/**
 * EIP-712 & EIP-3009 LocalSigner implementation for AgentPay.
 *
 * Uses viem for all cryptographic operations.
 * Enforces firewall reservation binding and secret redaction.
 */

import { parseSignature, recoverTypedDataAddress } from 'viem';
import { type PrivateKeyAccount, privateKeyToAccount } from 'viem/accounts';
import {
  PaymentAuthorization,
  type PaymentChallenge,
  SignatureData,
} from '../core/models.js';
import type { ReservationToken } from '../policy/models.js';
import {
  InvalidPrivateKeyError,
  ReservationMismatchError,
  SignerError,
  UnsupportedNetworkError,
} from './errors.js';
import type { ISigner, SignAuthorizationOptions } from './interfaces.js';

/** CAIP-2 parsing regex for eip155 namespace: eip155:<chain_id> */
const CAIP2_EIP155_RE = /^eip155:([0-9]+)$/;

/** Standard EIP-3009 message type definition for TransferWithAuthorization */
export const EIP3009_MESSAGE_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

/** Standard token names for major stablecoins */
export const DEFAULT_TOKEN_NAMES: Readonly<Record<string, string>> = Object.freeze({
  usdc: 'USD Coin',
  eurc: 'Euro Coin',
});

/**
 * Generate a cryptographically secure 32-byte hex nonce with 0x prefix.
 */
export function generateNonce(): `0x${string}` {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Buffer.from(bytes).toString('hex')}` as `0x${string}`;
}

/**
 * Extract the integer chain ID from a CAIP-2 network string.
 *
 * @param network CAIP-2 network identifier (e.g. 'eip155:84532').
 * @returns Integer chain ID.
 * @throws UnsupportedNetworkError If the network is not an eip155 EVM chain.
 */
export function parseCaip2ChainId(network: string): number {
  const match = CAIP2_EIP155_RE.exec(network.trim());
  if (!match || !match[1]) {
    throw new UnsupportedNetworkError(
      `Unsupported network identifier: ${JSON.stringify(network)}. ` +
        "LocalSigner only supports EVM chains conforming to 'eip155:<chainId>'.",
    );
  }
  return Number.parseInt(match[1], 10);
}

/**
 * Local private key signer for AgentPay clients.
 *
 * - Adheres to EIP-712 and EIP-3009 specifications.
 * - Uses viem strictly; implements zero custom cryptography.
 * - Enforces mandatory policy reservation verification before signing.
 * - Redacts private key in toString, inspect, and toJSON for financial safety.
 */
export class LocalSigner implements ISigner {
  readonly #account: PrivateKeyAccount;
  readonly #tokenNameMap: Map<string, string>;
  readonly address: `0x${string}`;

  constructor(
    privateKey: string | Uint8Array,
    options?: { tokenNameMap?: Record<string, string> },
  ) {
    try {
      let cleanKey: `0x${string}`;
      if (typeof privateKey === 'string') {
        const trimmed = privateKey.trim();
        cleanKey = (trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`) as `0x${string}`;
        if (!/^0x[0-9a-fA-F]{64}$/.test(cleanKey)) {
          throw new Error('Private key must be a 32-byte hex string');
        }
      } else if (privateKey instanceof Uint8Array) {
        if (privateKey.byteLength !== 32) {
          throw new Error(`Private key bytes must be 32 bytes, got ${privateKey.byteLength}`);
        }
        cleanKey = `0x${Buffer.from(privateKey).toString('hex')}` as `0x${string}`;
      } else {
        throw new TypeError(`privateKey must be string or Uint8Array, got ${typeof privateKey}`);
      }

      this.#account = privateKeyToAccount(cleanKey);
    } catch (exc) {
      throw new InvalidPrivateKeyError(
        `Failed to load EVM private key: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }

    this.address = this.#account.address.toLowerCase() as `0x${string}`;
    this.#tokenNameMap = new Map();
    if (options?.tokenNameMap) {
      for (const [k, v] of Object.entries(options.tokenNameMap)) {
        this.#tokenNameMap.set(k.toLowerCase(), v);
      }
    }
  }

  toString(): string {
    return `LocalSigner(address=${this.address})`;
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `<LocalSigner address=${this.address}>`;
  }

  toJSON(): Record<string, unknown> {
    return { address: this.address };
  }

  /**
   * Generate a new random LocalSigner using cryptographically secure randomness.
   */
  static generate(): LocalSigner {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return new LocalSigner(bytes);
  }

  /**
   * Resolve the EIP-712 domain token name for a payment challenge.
   */
  resolveTokenName(challenge: PaymentChallenge, explicitName?: string): string {
    if (explicitName) {
      return explicitName;
    }
    const assetLower = challenge.asset?.toLowerCase();
    if (assetLower && this.#tokenNameMap.has(assetLower)) {
      return this.#tokenNameMap.get(assetLower)!;
    }
    const symbolLower = challenge.assetSymbol?.toLowerCase();
    if (symbolLower && this.#tokenNameMap.has(symbolLower)) {
      return this.#tokenNameMap.get(symbolLower)!;
    }
    if (symbolLower && DEFAULT_TOKEN_NAMES[symbolLower]) {
      return DEFAULT_TOKEN_NAMES[symbolLower];
    }
    return challenge.assetSymbol || 'USD Coin';
  }

  /**
   * Build EIP-712 domain, types, and message dictionaries conforming to EIP-3009.
   */
  buildEip712Data(
    challenge: PaymentChallenge,
    nonce: string,
    options?: { tokenName?: string; tokenVersion?: string },
  ) {
    if (!challenge.network) {
      throw new UnsupportedNetworkError('PaymentChallenge network is required for EIP-3009 signing');
    }
    if (!challenge.asset) {
      throw new SignerError('PaymentChallenge asset is required for EIP-3009 signing');
    }
    if (!challenge.payee) {
      throw new SignerError('PaymentChallenge payee is required for EIP-3009 signing');
    }

    const chainId = parseCaip2ChainId(challenge.network);
    const domainName = this.resolveTokenName(challenge, options?.tokenName);
    const tokenVersion = options?.tokenVersion ?? '2';

    const domain = {
      name: domainName,
      version: tokenVersion,
      chainId,
      verifyingContract: challenge.asset as `0x${string}`,
    };

    const types = EIP3009_MESSAGE_TYPES;
    const normNonce = (nonce.startsWith('0x') ? nonce.toLowerCase() : `0x${nonce.toLowerCase()}`) as `0x${string}`;

    const message = {
      from: this.address,
      to: challenge.payee as `0x${string}`,
      value: challenge.amountBaseUnits,
      validAfter: BigInt(challenge.validAfter),
      validBefore: BigInt(challenge.validBefore),
      nonce: normNonce,
    };

    return { domain, types, message };
  }

  /**
   * Sign an EIP-712/3009 transfer authorization after verifying the policy reservation.
   *
   * Safety Guardrails:
   *   1. Verifies reservation.intentId === challenge.challengeId
   *   2. Verifies reservation.amount === challenge.amountBaseUnits
   *   3. Verifies reservation.expiresAt >= challenge.validBefore
   *
   * @returns PaymentAuthorization with cryptographic signature.
   */
  async signPaymentAuthorization(
    challenge: PaymentChallenge,
    reservation: ReservationToken,
    options?: SignAuthorizationOptions,
  ): Promise<PaymentAuthorization> {
    // Guardrail 1: Policy intent binding
    if (reservation.intentId !== challenge.challengeId) {
      throw new ReservationMismatchError(
        `Reservation intent_id (${JSON.stringify(reservation.intentId)}) does not match ` +
          `challenge_id (${JSON.stringify(challenge.challengeId)}). Refusing to sign.`,
      );
    }

    // Guardrail 2: Amount exact match
    if (reservation.amount !== challenge.amountBaseUnits) {
      throw new ReservationMismatchError(
        `Reservation amount (${reservation.amount.toString()}) does not match ` +
          `challenge amount (${challenge.amountBaseUnits.toString()}). Refusing to sign.`,
      );
    }

    // Guardrail 3: Expiration safety window
    if (reservation.expiresAt < challenge.validBefore) {
      throw new ReservationMismatchError(
        `Reservation expires_at (${reservation.expiresAt}) does not cover ` +
          `challenge valid_before (${challenge.validBefore}). Refusing to sign.`,
      );
    }

    const signNonce = options?.nonce ? (options.nonce.startsWith('0x') ? options.nonce : `0x${options.nonce}`) : generateNonce();

    const { domain, types, message } = this.buildEip712Data(challenge, signNonce, {
      tokenName: options?.tokenName,
      tokenVersion: options?.tokenVersion,
    });

    let rawSig: `0x${string}`;
    try {
      rawSig = await this.#account.signTypedData({
        domain,
        types,
        primaryType: 'TransferWithAuthorization',
        message,
      });
    } catch (exc) {
      throw new SignerError(
        `Cryptographic signing failed: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }

    const parsed = parseSignature(rawSig);
    const rHex = parsed.r;
    const sHex = parsed.s;
    const vVal = Number(parsed.v);

    const rClean = rHex.slice(2).padStart(64, '0');
    const sClean = sHex.slice(2).padStart(64, '0');
    const vHex = vVal.toString(16).padStart(2, '0');
    const serializedHex = `${rClean}${sClean}${vHex}`;

    const sigData = new SignatureData({
      v: vVal,
      r: rHex,
      s: sHex,
      serialized: serializedHex,
      compact: `0x${serializedHex}`,
    });

    return new PaymentAuthorization({
      version: '2.0',
      challengeId: challenge.challengeId,
      payer: this.address,
      scheme: challenge.scheme,
      nonce: signNonce as `0x${string}`,
      validAfter: challenge.validAfter,
      validBefore: challenge.validBefore,
      signature: sigData,
    });
  }

  /**
   * Verify that a PaymentAuthorization cryptographically matches the PaymentChallenge
   * and was signed by the expected payer.
   *
   * @returns True if signature is valid and signer matches expected payer; False otherwise.
   */
  static async verifyAuthorization(
    authorization: PaymentAuthorization,
    challenge: PaymentChallenge,
    options?: { expectedPayer?: string; tokenName?: string; tokenVersion?: string },
  ): Promise<boolean> {
    try {
      if (!challenge.network || !challenge.asset || !challenge.payee) {
        return false;
      }
      const targetPayer = (options?.expectedPayer ?? authorization.payer).toLowerCase();
      const chainId = parseCaip2ChainId(challenge.network);
      const symbolLower = challenge.assetSymbol?.toLowerCase();
      const domainName =
        options?.tokenName ??
        (symbolLower && DEFAULT_TOKEN_NAMES[symbolLower]) ??
        challenge.assetSymbol ??
        'USD Coin';
      const tokenVersion = options?.tokenVersion ?? '2';

      const domain = {
        name: domainName,
        version: tokenVersion,
        chainId,
        verifyingContract: challenge.asset as `0x${string}`,
      };

      const types = EIP3009_MESSAGE_TYPES;
      const normNonce = (
        authorization.nonce.startsWith('0x')
          ? authorization.nonce.toLowerCase()
          : `0x${authorization.nonce.toLowerCase()}`
      ) as `0x${string}`;

      const message = {
        from: authorization.payer,
        to: challenge.payee as `0x${string}`,
        value: challenge.amountBaseUnits,
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
        nonce: normNonce,
      };

      let sigHex: `0x${string}`;
      if (authorization.signature instanceof SignatureData) {
        sigHex = authorization.signature.compact;
      } else if (typeof authorization.signature === 'string') {
        const clean = authorization.signature.startsWith('0x')
          ? authorization.signature
          : `0x${authorization.signature}`;
        sigHex = clean.toLowerCase() as `0x${string}`;
      } else {
        return false;
      }

      const recovered = await recoverTypedDataAddress({
        domain,
        types,
        primaryType: 'TransferWithAuthorization',
        message,
        signature: sigHex,
      });

      return recovered.toLowerCase() === targetPayer;
    } catch {
      return false;
    }
  }
}
