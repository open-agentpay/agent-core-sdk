package x402

import (
	"strings"
	"testing"
)

func TestCodecsBase64URLHelpers(t *testing.T) {
	raw := []byte(`{"hello":"world","price":50000}`)
	encoded := Base64URLEncode(raw)
	if strings.Contains(encoded, "=") {
		t.Errorf("expected unpadded base64url, got '=' in %s", encoded)
	}

	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Errorf("roundtrip mismatch: got %s, want %s", decoded, raw)
	}

	// Test decoding with padding tolerated
	padded := encoded + "=="
	decodedPadded, err := Base64URLDecode(padded)
	if err != nil {
		t.Fatalf("padded decode failed: %v", err)
	}
	if string(decodedPadded) != string(raw) {
		t.Errorf("padded mismatch: got %s, want %s", decodedPadded, raw)
	}
}

func TestChallengeCodecsRoundtrip(t *testing.T) {
	ch := &PaymentChallenge{
		Version:     "2.0",
		ChallengeID: "ch_test_123",
		Network:     "eip155:84532",
		Asset:       "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
		AssetSymbol: "USDC",
		Decimals:    6,
		Amount:      "50000",
		Payee:       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Scheme:      "EIP-3009",
		ValidAfter:  1729000000,
		ValidBefore: 1729000300,
	}

	// 1. Base64URL serialization
	b64Header, err := EncodeChallenge(ch, true)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	if strings.HasPrefix(b64Header, "{") {
		t.Errorf("expected base64 string, got json")
	}

	parsed, err := DecodeChallenge(b64Header)
	if err != nil {
		t.Fatalf("decode challenge failed: %v", err)
	}
	if parsed.ChallengeID != ch.ChallengeID || parsed.Amount != ch.Amount {
		t.Errorf("decoded challenge fields mismatch: %+v", parsed)
	}

	// 2. Raw JSON string serialization
	jsonHeader, err := EncodeChallenge(ch, false)
	if err != nil {
		t.Fatalf("encode json failed: %v", err)
	}
	parsedJSON, err := DecodeChallenge(jsonHeader)
	if err != nil {
		t.Fatalf("decode json challenge failed: %v", err)
	}
	if parsedJSON.ChallengeID != ch.ChallengeID {
		t.Errorf("parsed json challenge mismatch")
	}

	// 3. Reject invalid versions & malformed payloads
	_, err = DecodeChallenge("not-valid-base64-or-json@@@")
	if err == nil {
		t.Errorf("expected error for malformed challenge")
	}

	_, err = DecodeChallenge(`{"version":"1.0","challengeId":"ch_1"}`)
	if err == nil {
		t.Errorf("expected error for unsupported version 1.0")
	}
}

func TestAuthorizationCodecsRoundtrip(t *testing.T) {
	auth := &PaymentAuthorization{
		Version:     "2.0",
		ChallengeID: "ch_test_123",
		Payer:       "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Scheme:      "EIP-3009",
		Nonce:       "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		ValidAfter:  1729000000,
		ValidBefore: 1729000300,
		Signature:   NewSignatureFromString("0xd90ab6b3serialized"),
	}

	encoded, err := EncodeAuthorization(auth, true)
	if err != nil {
		t.Fatalf("encode auth failed: %v", err)
	}

	parsed, err := DecodeAuthorization(encoded)
	if err != nil {
		t.Fatalf("decode auth failed: %v", err)
	}
	if parsed.Payer != strings.ToLower(auth.Payer) || parsed.Nonce != strings.ToLower(auth.Nonce) {
		t.Errorf("auth fields mismatch: %+v", parsed)
	}
	if parsed.Signature.Hex() != "0xd90ab6b3serialized" {
		t.Errorf("expected signature hex 0xd90ab6b3serialized, got %s", parsed.Signature.Hex())
	}
}

func TestDecodeAuthorizationWithStructuredSignatureObject(t *testing.T) {
	// Payload with signature as an object (v, r, s, serialized, compact), as sent by Python/TypeScript SDKs
	rawJSON := `{
		"version": "2.0",
		"challengeId": "ch_0b9b3a11bf5f0a4b929300f0",
		"payer": "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"scheme": "EIP-3009",
		"nonce": "0x779a25ffef341f1b78c6a5bfdced2fe1b08def5327b13a4808c6742c2ed1ed1a",
		"validAfter": 1792839979,
		"validBefore": 1792840279,
		"signature": {
			"v": 28,
			"r": "0x4e7d0b7600c3764fc84853832c295cdab973e09f469fc99edd0d95d401adbac4",
			"s": "0x0da592de707c994d029160d97dc38f00b9ba9c3bcdc97369b151aa63bf28ca89",
			"serialized": "4e7d0b7600c3764fc84853832c295cdab973e09f469fc99edd0d95d401adbac40da592de707c994d029160d97dc38f00b9ba9c3bcdc97369b151aa63bf28ca891c",
			"compact": "0x4e7d0b7600c3764fc84853832c295cdab973e09f469fc99edd0d95d401adbac40da592de707c994d029160d97dc38f00b9ba9c3bcdc97369b151aa63bf28ca891c"
		}
	}`

	auth, err := DecodeAuthorization(rawJSON)
	if err != nil {
		t.Fatalf("failed to decode authorization with object signature: %v", err)
	}

	if auth.Signature.V != 28 {
		t.Errorf("expected signature V=28, got %d", auth.Signature.V)
	}
	if auth.Signature.R != "0x4e7d0b7600c3764fc84853832c295cdab973e09f469fc99edd0d95d401adbac4" {
		t.Errorf("unexpected R: %s", auth.Signature.R)
	}
	if auth.Signature.Compact != "0x4e7d0b7600c3764fc84853832c295cdab973e09f469fc99edd0d95d401adbac40da592de707c994d029160d97dc38f00b9ba9c3bcdc97369b151aa63bf28ca891c" {
		t.Errorf("unexpected Compact: %s", auth.Signature.Compact)
	}

	// Base64URL encoded format test
	encodedBase64 := Base64URLEncode([]byte(rawJSON))
	authB64, err := DecodeAuthorization(encodedBase64)
	if err != nil {
		t.Fatalf("failed to decode base64 authorization: %v", err)
	}
	if authB64.Signature.V != 28 {
		t.Errorf("expected b64 signature V=28, got %d", authB64.Signature.V)
	}
}
