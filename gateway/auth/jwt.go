package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrTokenInvalid   = errors.New("invalid token format or signature")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenMalformed = errors.New("malformed token payload")
)

// Header represents standard JWT JOSE header.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims represents JWT payload claims.
type Claims struct {
	Subject   string `json:"sub"`   // member_id
	Email     string `json:"email"` // user email
	TenantID  string `json:"tid"`   // tenant_id
	Role      string `json:"role"`  // member role
	IssuedAt  int64  `json:"iat"`   // unix timestamp
	ExpiresAt int64  `json:"exp"`   // unix timestamp
}

// JWTManager handles signing and verification of HS256 tokens.
type JWTManager struct {
	secretKey     []byte
	tokenDuration time.Duration
}

// NewJWTManager constructs a new JWTManager.
func NewJWTManager(secretKey string, tokenDuration time.Duration) (*JWTManager, error) {
	if strings.TrimSpace(secretKey) == "" {
		return nil, errors.New("jwt secret key cannot be empty: refusing to initialize with insecure defaults")
	}
	if tokenDuration == 0 {
		tokenDuration = 24 * time.Hour
	}
	return &JWTManager{
		secretKey:     []byte(secretKey),
		tokenDuration: tokenDuration,
	}, nil
}

// MustNewJWTManager constructs a new JWTManager or panics on error. Useful in tests and bootstrap.
func MustNewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	mgr, err := NewJWTManager(secretKey, tokenDuration)
	if err != nil {
		panic(err)
	}
	return mgr
}

// GenerateToken signs a new JWT token for the specified user and tenant.
func (m *JWTManager) GenerateToken(memberID, email, tenantID, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		Subject:   memberID,
		Email:     email,
		TenantID:  tenantID,
		Role:      role,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(m.tokenDuration).Unix(),
	}

	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	payloadToSign := headerB64 + "." + claimsB64
	signature := m.sign(payloadToSign)
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return payloadToSign + "." + sigB64, nil
}

// ValidateToken verifies token signature and expiration, returning parsed Claims.
func (m *JWTManager) ValidateToken(tokenStr string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}

	payloadToSign := parts[0] + "." + parts[1]
	expectedSig := m.sign(payloadToSign)

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrTokenInvalid
	}

	if !hmac.Equal(sigBytes, expectedSig) {
		return nil, ErrTokenInvalid
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	if time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

func (m *JWTManager) sign(data string) []byte {
	h := hmac.New(sha256.New, m.secretKey)
	h.Write([]byte(data))
	return h.Sum(nil)
}
