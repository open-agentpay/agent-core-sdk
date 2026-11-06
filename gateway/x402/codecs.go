package x402

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var walletNoncePattern = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

func decodeHeaderJSON(headerVal string) ([]byte, error) {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "" {
		return nil, ErrEmptyHeader
	}
	if strings.HasPrefix(headerVal, "{") {
		return []byte(headerVal), nil
	}
	decoded, err := Base64URLDecode(headerVal)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrMalformedHeader, err)
	}
	return decoded, nil
}

// DecodeWalletAuthorization parses and validates the AgentPay virtual-wallet extension payload.
func DecodeWalletAuthorization(headerVal string) (*WalletAuthorization, error) {
	raw, err := decodeHeaderJSON(headerVal)
	if err != nil {
		return nil, err
	}
	var auth WalletAuthorization
	if err := json.Unmarshal(raw, &auth); err != nil {
		return nil, fmt.Errorf("%w: json parse error: %v", ErrMalformedHeader, err)
	}
	auth.Nonce = strings.ToLower(strings.TrimSpace(auth.Nonce))
	if auth.Version != DefaultVersion || auth.ChallengeID == "" || auth.Scheme != WalletScheme || auth.Amount == "" || auth.ResourceURI == "" || auth.RequestBinding == "" || !walletNoncePattern.MatchString(auth.Nonce) || auth.ValidBefore <= auth.ValidAfter {
		return nil, fmt.Errorf("%w: invalid agentpay-wallet authorization fields", ErrMissingRequiredField)
	}
	if amount, err := strconv.ParseInt(auth.Amount, 10, 64); err != nil || amount <= 0 {
		return nil, fmt.Errorf("%w: amount must be a positive int64 decimal string", ErrMalformedHeader)
	}
	return &auth, nil
}

var (
	ErrEmptyHeader          = errors.New("header value is empty")
	ErrMalformedHeader      = errors.New("malformed header payload")
	ErrUnsupportedVersion   = errors.New("unsupported x402 protocol version")
	ErrMissingRequiredField = errors.New("missing required field in x402 payload")
)

// Base64URLEncode encodes bytes into unpadded RFC 4648 URL-safe base64 string.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes an RFC 4648 URL-safe base64 string (handles padded or unpadded).
func Base64URLDecode(s string) ([]byte, error) {
	// Trim standard padding if present
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// EncodeChallenge serializes a PaymentChallenge into a header string (Base64URL or JSON).
func EncodeChallenge(ch *PaymentChallenge, base64URL bool) (string, error) {
	if ch == nil {
		return "", errors.New("challenge cannot be nil")
	}
	bytes, err := json.Marshal(ch)
	if err != nil {
		return "", fmt.Errorf("failed to marshal challenge: %w", err)
	}
	if base64URL {
		return Base64URLEncode(bytes), nil
	}
	return string(bytes), nil
}

// DecodeChallenge parses a PAYMENT-REQUIRED header value (auto-detects base64 or JSON).
func DecodeChallenge(headerVal string) (*PaymentChallenge, error) {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "" {
		return nil, ErrEmptyHeader
	}

	var rawJSON []byte
	if strings.HasPrefix(headerVal, "{") {
		rawJSON = []byte(headerVal)
	} else {
		decoded, err := Base64URLDecode(headerVal)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrMalformedHeader, err)
		}
		rawJSON = decoded
	}

	var ch PaymentChallenge
	if err := json.Unmarshal(rawJSON, &ch); err != nil {
		return nil, fmt.Errorf("%w: json parse error: %v", ErrMalformedHeader, err)
	}

	// Validate required fields
	if ch.Version != "2.0" {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedVersion, ch.Version)
	}
	if ch.ChallengeID == "" {
		return nil, fmt.Errorf("%w: challengeId", ErrMissingRequiredField)
	}
	if ch.Network == "" {
		return nil, fmt.Errorf("%w: network", ErrMissingRequiredField)
	}
	if ch.Asset == "" {
		return nil, fmt.Errorf("%w: asset", ErrMissingRequiredField)
	}
	if ch.Amount == "" {
		return nil, fmt.Errorf("%w: amount", ErrMissingRequiredField)
	}
	if ch.Payee == "" {
		return nil, fmt.Errorf("%w: payee", ErrMissingRequiredField)
	}
	if ch.ValidBefore <= ch.ValidAfter {
		return nil, fmt.Errorf("%w: validBefore must be greater than validAfter", ErrMalformedHeader)
	}

	return &ch, nil
}

// EncodeAuthorization serializes a PaymentAuthorization into a header string.
func EncodeAuthorization(auth *PaymentAuthorization, base64URL bool) (string, error) {
	if auth == nil {
		return "", errors.New("authorization cannot be nil")
	}
	bytes, err := json.Marshal(auth)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization: %w", err)
	}
	if base64URL {
		return Base64URLEncode(bytes), nil
	}
	return string(bytes), nil
}

// DecodeAuthorization parses a PAYMENT-SIGNATURE header value.
func DecodeAuthorization(headerVal string) (*PaymentAuthorization, error) {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "" {
		return nil, ErrEmptyHeader
	}

	var rawJSON []byte
	if strings.HasPrefix(headerVal, "{") {
		rawJSON = []byte(headerVal)
	} else {
		decoded, err := Base64URLDecode(headerVal)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrMalformedHeader, err)
		}
		rawJSON = decoded
	}

	var auth PaymentAuthorization
	if err := json.Unmarshal(rawJSON, &auth); err != nil {
		return nil, fmt.Errorf("%w: json parse error: %v", ErrMalformedHeader, err)
	}

	if auth.Version != "2.0" {
		return nil, fmt.Errorf("%w: got %q", ErrUnsupportedVersion, auth.Version)
	}
	if auth.ChallengeID == "" {
		return nil, fmt.Errorf("%w: challengeId", ErrMissingRequiredField)
	}
	// SECURITY-REVIEW: normalize payer address and nonce to lowercase to prevent
	// case-variant replay bypasses across x402 authorization headers (P0-4).
	auth.Payer = strings.ToLower(strings.TrimSpace(auth.Payer))
	auth.Nonce = strings.ToLower(strings.TrimSpace(auth.Nonce))
	if auth.Payer == "" {
		return nil, fmt.Errorf("%w: payer", ErrMissingRequiredField)
	}
	if auth.Nonce == "" {
		return nil, fmt.Errorf("%w: nonce", ErrMissingRequiredField)
	}
	if auth.Signature.IsEmpty() {
		return nil, fmt.Errorf("%w: signature", ErrMissingRequiredField)
	}

	return &auth, nil
}
