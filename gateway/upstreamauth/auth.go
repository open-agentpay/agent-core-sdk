package upstreamauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type FieldKind string

const (
	KindText     FieldKind = "text"
	KindPassword FieldKind = "password"
	KindSelect   FieldKind = "select"
	KindNumber   FieldKind = "number"
	KindSwitch   FieldKind = "switch"
	KindTextarea FieldKind = "textarea"
)

// ErrMasterKeyNotConfigured is returned when encryption or decryption is attempted without a configured master key.
var ErrMasterKeyNotConfigured = errors.New("upstream master key is not configured: set AGENTPAY_UPSTREAM_MASTER_KEY or configure keyring")

// FieldSchema defines an input field for the frontend schema-driven form.
type FieldSchema struct {
	Key          string    `json:"key"`
	Label        string    `json:"label"`
	Kind         FieldKind `json:"kind"`
	Options      []string  `json:"options,omitempty"`
	Secret       bool      `json:"secret"`
	Required     bool      `json:"required"`
	DefaultValue any       `json:"default_value,omitempty"`
	Description  string    `json:"description,omitempty"`
}

// AuthTypeSchema defines the schema for a supported upstream authentication strategy.
type AuthTypeSchema struct {
	Type        string        `json:"type"`
	Label       string        `json:"label"`
	Description string        `json:"description"`
	Fields      []FieldSchema `json:"fields"`
}

// UpstreamAuthConfig holds the configured authentication type, non-sensitive params, and encrypted secrets.
type UpstreamAuthConfig struct {
	Type       string            `json:"type"`                 // "none", "api_key", "bearer", "basic", etc.
	Params     map[string]any    `json:"params,omitempty"`     // Non-sensitive configuration, echoed
	Secrets    map[string]string `json:"secrets,omitempty"`    // Write-only secrets, never echoed in responses
	SecretEnc  []byte            `json:"secret_enc,omitempty"` // AES-GCM encrypted ciphertext
	KeyVersion int               `json:"key_version"`
	HasSecret  bool              `json:"has_secret"`           // Indicator whether secrets are configured
	UpdatedAt  int64             `json:"updated_at,omitempty"`
}

// Authenticator defines the interface for an upstream auth strategy.
type Authenticator interface {
	Type() string
	Schema() AuthTypeSchema
	Validate(params map[string]any, secrets map[string]string) error
	Apply(ctx context.Context, req *http.Request, params map[string]any, secrets map[string]string) error
}

var (
	registryLock sync.RWMutex
	registry     = map[string]Authenticator{}
)

// Register registers an authenticator into the global registry.
func Register(a Authenticator) {
	registryLock.Lock()
	defer registryLock.Unlock()
	registry[a.Type()] = a
}

// Get returns the registered authenticator for the given authType.
func Get(authType string) (Authenticator, bool) {
	registryLock.RLock()
	defer registryLock.RUnlock()
	a, ok := registry[authType]
	return a, ok
}

// ListSchemas returns all registered schemas in a consistent priority order.
func ListSchemas() []AuthTypeSchema {
	registryLock.RLock()
	defer registryLock.RUnlock()
	order := []string{
		"none",
		"api_key",
		"bearer",
		"basic",
		"oauth2_client_credentials",
		"hmac_sign",
		"custom_template",
	}
	schemas := make([]AuthTypeSchema, 0, len(registry))
	for _, t := range order {
		if a, ok := registry[t]; ok {
			schemas = append(schemas, a.Schema())
		}
	}
	for t, a := range registry {
		found := false
		for _, o := range order {
			if o == t {
				found = true
				break
			}
		}
		if !found {
			schemas = append(schemas, a.Schema())
		}
	}
	return schemas
}

// ----------------------------------------------------------------------------
// AES-256-GCM Envelope Encryption & Versioned KeyRing for Secrets
// # SECURITY-REVIEW
// ----------------------------------------------------------------------------

var (
	keyRingMu      sync.RWMutex
	activeVersion  int
	masterKeyRing  = map[int][]byte{}
)

// ParseMasterKey parses a 32-byte AES-256 key from raw 32-byte string, 64-char hex, or base64.
func ParseMasterKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ErrMasterKeyNotConfigured
	}
	if len(trimmed) == 32 {
		return []byte(trimmed), nil
	}
	if len(trimmed) == 64 {
		if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	return nil, errors.New("master key must be 32 bytes (raw, 64-char hex, or base64)")
}

// ConfigureKeyRing configures the active master key and optional historical keys for rotation.
func ConfigureKeyRing(currentVersion int, activeKeyRaw string, previousKeysRaw map[int]string) error {
	if currentVersion <= 0 {
		currentVersion = 1
	}
	activeKey, err := ParseMasterKey(activeKeyRaw)
	if err != nil {
		return fmt.Errorf("invalid active master key: %w", err)
	}

	newRing := make(map[int][]byte, len(previousKeysRaw)+1)
	for ver, raw := range previousKeysRaw {
		if ver <= 0 {
			return fmt.Errorf("key version must be positive, got %d", ver)
		}
		k, err := ParseMasterKey(raw)
		if err != nil {
			return fmt.Errorf("invalid previous master key for version %d: %w", ver, err)
		}
		newRing[ver] = k
	}
	newRing[currentVersion] = activeKey

	keyRingMu.Lock()
	defer keyRingMu.Unlock()
	activeVersion = currentVersion
	masterKeyRing = newRing
	return nil
}

// ResetKeyRing clears all configured master keys (used in tests).
func ResetKeyRing() {
	keyRingMu.Lock()
	defer keyRingMu.Unlock()
	activeVersion = 0
	masterKeyRing = map[int][]byte{}
}

// CurrentKeyVersion returns the active master key version (or 0 if unconfigured).
func CurrentKeyVersion() int {
	keyRingMu.RLock()
	ver := activeVersion
	keyRingMu.RUnlock()
	if ver > 0 {
		return ver
	}
	if envKey := strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY")); envKey != "" {
		if err := loadFromEnvIfUnconfigured(); err == nil {
			keyRingMu.RLock()
			ver = activeVersion
			keyRingMu.RUnlock()
		}
	}
	return ver
}

func loadFromEnvIfUnconfigured() error {
	envKey := strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY"))
	if envKey == "" {
		return ErrMasterKeyNotConfigured
	}
	ver := 1
	if vStr := strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY_VERSION")); vStr != "" {
		if parsed, err := strconv.Atoi(vStr); err == nil && parsed > 0 {
			ver = parsed
		}
	}
	prevMap := make(map[int]string)
	if prevEnv := strings.TrimSpace(os.Getenv("AGENTPAY_UPSTREAM_PREVIOUS_MASTER_KEYS")); prevEnv != "" {
		for _, pair := range strings.Split(prevEnv, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				if pVer, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil && pVer > 0 {
					prevMap[pVer] = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ConfigureKeyRing(ver, envKey, prevMap)
}

func resolveActiveKey() ([]byte, int, error) {
	keyRingMu.RLock()
	ver := activeVersion
	k := masterKeyRing[ver]
	keyRingMu.RUnlock()
	if len(k) == 32 && ver > 0 {
		cp := make([]byte, 32)
		copy(cp, k)
		return cp, ver, nil
	}
	if err := loadFromEnvIfUnconfigured(); err != nil {
		return nil, 0, err
	}
	keyRingMu.RLock()
	ver = activeVersion
	k = masterKeyRing[ver]
	keyRingMu.RUnlock()
	if len(k) != 32 {
		return nil, 0, ErrMasterKeyNotConfigured
	}
	cp := make([]byte, 32)
	copy(cp, k)
	return cp, ver, nil
}

func resolveCandidateKeys(preferredVersion int) ([][]byte, error) {
	keyRingMu.RLock()
	ringLen := len(masterKeyRing)
	keyRingMu.RUnlock()
	if ringLen == 0 {
		if err := loadFromEnvIfUnconfigured(); err != nil {
			return nil, err
		}
	}

	keyRingMu.RLock()
	defer keyRingMu.RUnlock()
	if len(masterKeyRing) == 0 {
		return nil, ErrMasterKeyNotConfigured
	}

	var candidates [][]byte
	seen := make(map[int]bool)
	if preferredVersion > 0 {
		if k, ok := masterKeyRing[preferredVersion]; ok && len(k) == 32 {
			cp := make([]byte, 32)
			copy(cp, k)
			candidates = append(candidates, cp)
			seen[preferredVersion] = true
		}
	}
	if activeVersion > 0 && !seen[activeVersion] {
		if k, ok := masterKeyRing[activeVersion]; ok && len(k) == 32 {
			cp := make([]byte, 32)
			copy(cp, k)
			candidates = append(candidates, cp)
			seen[activeVersion] = true
		}
	}
	versions := make([]int, 0, len(masterKeyRing))
	for v := range masterKeyRing {
		if !seen[v] {
			versions = append(versions, v)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(versions)))
	for _, v := range versions {
		k := masterKeyRing[v]
		if len(k) == 32 {
			cp := make([]byte, 32)
			copy(cp, k)
			candidates = append(candidates, cp)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrMasterKeyNotConfigured
	}
	return candidates, nil
}

// EncryptSecretsVersioned encrypts secrets using the active master key in the keyring and returns the ciphertext and key version.
func EncryptSecretsVersioned(secrets map[string]string) ([]byte, int, error) {
	key, ver, err := resolveActiveKey()
	if err != nil {
		return nil, 0, err
	}
	ct, err := EncryptSecrets(secrets, key)
	if err != nil {
		return nil, 0, err
	}
	return ct, ver, nil
}

// DecryptSecretsVersioned decrypts ciphertext using the specified keyVersion (or fallback versions in the keyring).
func DecryptSecretsVersioned(ciphertext []byte, keyVersion int) (map[string]string, error) {
	if len(ciphertext) == 0 {
		return map[string]string{}, nil
	}
	candidates, err := resolveCandidateKeys(keyVersion)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, k := range candidates {
		dec, err := decryptWithKey(ciphertext, k)
		if err == nil {
			return dec, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// ReencryptSecrets decrypts ciphertext with old key version and re-encrypts with the current active key version.
func ReencryptSecrets(ciphertext []byte, keyVersion int) ([]byte, int, error) {
	secrets, err := DecryptSecretsVersioned(ciphertext, keyVersion)
	if err != nil {
		return nil, 0, err
	}
	return EncryptSecretsVersioned(secrets)
}

// EncryptSecrets encrypts the secrets map with AES-256-GCM using the provided 32-byte key (or active keyring if key is empty).
func EncryptSecrets(secrets map[string]string, key []byte) ([]byte, error) {
	if len(key) == 0 {
		resolved, _, err := resolveActiveKey()
		if err != nil {
			return nil, err
		}
		key = resolved
	}
	if len(key) != 32 {
		return nil, errors.New("master key must be exactly 32 bytes for AES-256")
	}
	data, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("marshal secrets: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptSecrets decrypts the AES-256-GCM ciphertext back into the secrets map.
func DecryptSecrets(ciphertext []byte, key []byte) (map[string]string, error) {
	if len(ciphertext) == 0 {
		return map[string]string{}, nil
	}
	if len(key) == 0 {
		return DecryptSecretsVersioned(ciphertext, 0)
	}
	return decryptWithKey(ciphertext, key)
}

func decryptWithKey(ciphertext []byte, key []byte) (map[string]string, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be exactly 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}

	var secrets map[string]string
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("unmarshal secrets: %w", err)
	}
	return secrets, nil
}
