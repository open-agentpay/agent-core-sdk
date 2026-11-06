package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	defaultIterations = 10000
	saltLength        = 16
	keyLength         = 32
)

var (
	ErrInvalidPasswordHash = errors.New("invalid password hash format")
	ErrPasswordMismatch    = errors.New("password does not match")
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters long")
)

// HashPassword hashes a plain text password using PBKDF2-HMAC-SHA256.
// Output format: $pbkdf2-sha256$i=10000$<salt_hex>$<hash_hex>
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrPasswordTooShort
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}

	hash := deriveKey([]byte(password), salt, defaultIterations, keyLength)
	return fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s", defaultIterations, hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

// VerifyPassword checks if a plain password matches the stored PBKDF2-HMAC-SHA256 hash.
func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	// Expected parts: ["", "pbkdf2-sha256", "i=10000", "<salt_hex>", "<hash_hex>"]
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return false
	}

	iterStr := strings.TrimPrefix(parts[2], "i=")
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations <= 0 {
		return false
	}

	salt, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}

	expectedHash, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}

	derived := deriveKey([]byte(password), salt, iterations, len(expectedHash))
	return subtle.ConstantTimeCompare(derived, expectedHash) == 1
}

// deriveKey computes standard PBKDF2 with HMAC-SHA256 (RFC 8018).
func deriveKey(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	prf.Reset()
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1}) // Block 1
	u := prf.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 1; i < iterations; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(nil)
		for j := 0; j < len(result); j++ {
			result[j] ^= u[j]
		}
	}

	if keyLen > len(result) {
		keyLen = len(result)
	}
	return result[:keyLen]
}
