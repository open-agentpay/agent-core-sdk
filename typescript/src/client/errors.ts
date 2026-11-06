/**
 * Signer and Client Exceptions for AgentPay.
 */

export class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClientError';
  }
}

export class SignerError extends ClientError {
  constructor(message: string) {
    super(message);
    this.name = 'SignerError';
  }
}

export class InvalidPrivateKeyError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPrivateKeyError';
  }
}

export class UnsupportedNetworkError extends SignerError {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedNetworkError';
  }
}

export class ReservationMismatchError extends SignerError {
  /**
   * Raised when an approved ReservationToken does not match the PaymentChallenge.
   * Critical financial firewall guardrail violation.
   */
  constructor(message: string) {
    super(message);
    this.name = 'ReservationMismatchError';
  }
}
