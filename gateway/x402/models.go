// Package x402 implements x402 V2 payment challenge generation, header codecs,
// cryptographic verification, and dual-path execution for AgentPay Go Gateway (T2.3).
package x402

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	HeaderPaymentRequired  = "PAYMENT-REQUIRED"
	HeaderPaymentSignature = "PAYMENT-SIGNATURE"
	HeaderIdempotencyKey   = "Idempotency-Key"
	DefaultVersion         = "2.0"
	DefaultScheme          = "EIP-3009"
	WalletScheme           = "agentpay-wallet"
	DefaultChallengeTTL    = 300 * time.Second // 5 minutes
)

// PaymentChallenge represents the structured 402 challenge issued to the buyer.
type PaymentChallenge struct {
	Version        string                 `json:"version"`
	ChallengeID    string                 `json:"challengeId"`
	Network        string                 `json:"network"` // CAIP-2, e.g. eip155:84532
	Asset          string                 `json:"asset"`   // Token contract address
	AssetSymbol    string                 `json:"assetSymbol"`
	Decimals       int                    `json:"decimals"`
	Amount         string                 `json:"amount"` // Base units integer string
	Payee          string                 `json:"payee"`  // Payee treasury address
	Scheme         string                 `json:"scheme"` // EIP-3009
	ValidAfter     int64                  `json:"validAfter"`
	ValidBefore    int64                  `json:"validBefore"`
	FacilitatorURL string                 `json:"facilitatorUrl,omitempty"`
	ResourceURI    string                 `json:"resourceUri,omitempty"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
}

// WalletAuthorization is the AgentPay wallet-specific PAYMENT-SIGNATURE payload.
// It is authenticated by the API key and never represents an EIP-712 signature.
type WalletAuthorization struct {
	Version        string `json:"version"`
	ChallengeID    string `json:"challengeId"`
	Scheme         string `json:"scheme"`
	Nonce          string `json:"nonce"`
	ValidAfter     int64  `json:"validAfter"`
	ValidBefore    int64  `json:"validBefore"`
	Amount         string `json:"amount"`
	ResourceURI    string `json:"resourceUri"`
	RequestBinding string `json:"requestBinding"`
}

// ComputeRequestBinding implements the cross-language canonical request digest in the wallet scheme spec.
func ComputeRequestBinding(method string, requestURL *url.URL, body []byte) string {
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	bodyDigest := sha256.Sum256(body)
	canonical := strings.ToUpper(method) + "\n" + path + "\n" + requestURL.RawQuery + "\n" + hex.EncodeToString(bodyDigest[:])
	digest := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// SignatureData holds components of the EIP-712 / ECDSA signature.
// Aligned with facilitator-go and agentpay Python client models.
// Supports both a structured object (v, r, s, serialized, compact) and a hex string ("0x...").
type SignatureData struct {
	V          uint8  `json:"v,omitempty"`
	R          string `json:"r,omitempty"`
	S          string `json:"s,omitempty"`
	Serialized string `json:"serialized,omitempty"`
	Compact    string `json:"compact,omitempty"`
	rawString  string `json:"-"`
}

// Hex returns the normalized 0x hex representation of the signature.
func (s *SignatureData) Hex() string {
	if s == nil {
		return ""
	}
	if s.Compact != "" {
		return s.Compact
	}
	if s.Serialized != "" {
		if strings.HasPrefix(s.Serialized, "0x") {
			return s.Serialized
		}
		return "0x" + s.Serialized
	}
	if s.R != "" && s.S != "" {
		rClean := strings.TrimPrefix(s.R, "0x")
		sClean := strings.TrimPrefix(s.S, "0x")
		vHex := fmt.Sprintf("%02x", s.V)
		return "0x" + rClean + sClean + vHex
	}
	if s.rawString != "" {
		return s.rawString
	}
	return ""
}

// IsEmpty checks if signature data is empty.
func (s *SignatureData) IsEmpty() bool {
	if s == nil {
		return true
	}
	return s.Hex() == "" && s.V == 0 && s.R == "" && s.S == ""
}

// NewSignatureFromString constructs a SignatureData from a hex string.
func NewSignatureFromString(sig string) SignatureData {
	clean := strings.TrimPrefix(sig, "0x")
	return SignatureData{
		Compact:    "0x" + clean,
		Serialized: clean,
		rawString:  sig,
	}
}

// UnmarshalJSON supports signature as either an object or a hex string.
func (s *SignatureData) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == `""` || string(data) == "null" {
		return nil
	}

	// Handle string format: "0x..."
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		s.rawString = str
		clean := strings.TrimPrefix(str, "0x")
		s.Serialized = clean
		s.Compact = "0x" + clean
		return nil
	}

	// Handle object format: {"v": 28, "r": "...", ...}
	type Alias SignatureData
	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*s = SignatureData(alias)
	if s.Compact == "" && s.Serialized != "" {
		s.Compact = "0x" + strings.TrimPrefix(s.Serialized, "0x")
	}
	return nil
}

// MarshalJSON marshals signature as an object if components exist, or as string if only raw string exists.
func (s SignatureData) MarshalJSON() ([]byte, error) {
	if s.V != 0 || s.R != "" || s.S != "" {
		type Alias SignatureData
		return json.Marshal(Alias(s))
	}
	if s.Compact != "" {
		return json.Marshal(s.Compact)
	}
	if s.Serialized != "" {
		return json.Marshal(s.Serialized)
	}
	if s.rawString != "" {
		return json.Marshal(s.rawString)
	}
	return []byte(`""`), nil
}

// PaymentAuthorization represents the buyer's signed payment authorization payload.
type PaymentAuthorization struct {
	Version     string        `json:"version"`
	ChallengeID string        `json:"challengeId"`
	Payer       string        `json:"payer"`  // Payer signer address
	Scheme      string        `json:"scheme"` // EIP-3009
	Nonce       string        `json:"nonce"`  // 32-byte hex nonce
	ValidAfter  int64         `json:"validAfter"`
	ValidBefore int64         `json:"validBefore"`
	Signature   SignatureData `json:"signature"` // Serialized signature (0x...) or structured object
}

// NewChallenge generates a fresh PaymentChallenge with a random challenge ID.
func NewChallenge(network, asset, assetSymbol string, decimals int, amount, payee, facilitatorURL, resourceURI string, ttl time.Duration) *PaymentChallenge {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	now := time.Now().Unix()
	return &PaymentChallenge{
		Version:        DefaultVersion,
		ChallengeID:    generateChallengeID(),
		Network:        network,
		Asset:          asset,
		AssetSymbol:    assetSymbol,
		Decimals:       decimals,
		Amount:         amount,
		Payee:          payee,
		Scheme:         DefaultScheme,
		ValidAfter:     now,
		ValidBefore:    now + int64(ttl.Seconds()),
		FacilitatorURL: facilitatorURL,
		ResourceURI:    resourceURI,
	}
}

// ParseCAIP2 parses an EIP-155 CAIP-2 network string into namespace and chain ID.
func ParseCAIP2(network string) (string, int64, error) {
	parts := strings.Split(network, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid CAIP-2 identifier: %q (expected format 'namespace:reference')", network)
	}
	var chainID int64
	_, err := fmt.Sscanf(parts[1], "%d", &chainID)
	if err != nil || chainID <= 0 {
		return "", 0, fmt.Errorf("invalid CAIP-2 chain ID reference: %q", parts[1])
	}
	return parts[0], chainID, nil
}

func generateChallengeID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "ch_" + hex.EncodeToString(b)
}
