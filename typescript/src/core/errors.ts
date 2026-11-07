/**
 * x402 V2 Protocol Errors & Error Codes.
 *
 * Adheres strictly to the x402 V2 specification and conformance test suite.
 */

export enum X402ErrorCode {
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  NETWORK_NOT_WHITELISTED = 'NETWORK_NOT_WHITELISTED',
  INVALID_CAIP2_NETWORK = 'INVALID_CAIP2_NETWORK',
  INVALID_ADDRESS = 'INVALID_ADDRESS',
  INVALID_AMOUNT_FORMAT = 'INVALID_AMOUNT_FORMAT',
  INVALID_TIME_WINDOW = 'INVALID_TIME_WINDOW',
  INVALID_SCHEME = 'INVALID_SCHEME',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  INVALID_NONCE = 'INVALID_NONCE',
  MALFORMED_HEADER = 'MALFORMED_HEADER',
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
  CHALLENGE_EXPIRED = 'CHALLENGE_EXPIRED',
}

export class X402Error extends Error {
  readonly code?: X402ErrorCode;

  constructor(message: string, code?: X402ErrorCode) {
    super(message);
    this.name = 'X402Error';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class X402ValidationError extends X402Error {
  constructor(message: string, code?: X402ErrorCode) {
    super(message, code);
    this.name = 'X402ValidationError';
  }
}

export class X402DecodeError extends X402Error {
  constructor(message: string, code?: X402ErrorCode) {
    super(message, code);
    this.name = 'X402DecodeError';
  }
}

export class X402EncodeError extends X402Error {
  constructor(message: string, code?: X402ErrorCode) {
    super(message, code);
    this.name = 'X402EncodeError';
  }
}
