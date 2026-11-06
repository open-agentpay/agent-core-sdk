// Package config manages configuration loading, environment overrides, and schema validation
// for AgentPay Go Gateway.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig defines HTTP network listener parameters.
type ServerConfig struct {
	Host                   string  `yaml:"host"`
	Port                   int     `yaml:"port"`
	ReadTimeoutSeconds     float64 `yaml:"read_timeout_seconds"`
	WriteTimeoutSeconds    float64 `yaml:"write_timeout_seconds"`
	IdleTimeoutSeconds     float64 `yaml:"idle_timeout_seconds"`
	ShutdownTimeoutSeconds float64 `yaml:"shutdown_timeout_seconds"`
}

// DatabaseConfig defines PostgreSQL connection parameters.
type DatabaseConfig struct {
	PostgresURL            string `yaml:"postgres_url"`
	MaxOpenConns           int    `yaml:"max_open_conns"`
	MaxIdleConns           int    `yaml:"max_idle_conns"`
	ConnMaxLifetimeSeconds int    `yaml:"conn_max_lifetime_seconds"`
}

// FacilitatorConfig defines connection to the batch settlement facilitator.
type FacilitatorConfig struct {
	URL            string  `yaml:"url"`
	APIKey         string  `yaml:"api_key"`
	TimeoutSeconds float64 `yaml:"timeout_seconds"`
}

// SettlementConfig defines default settlement assets and networks.
type SettlementConfig struct {
	DefaultNetwork       string `yaml:"default_network"`
	DefaultAsset         string `yaml:"default_asset"`
	DefaultAssetSymbol   string `yaml:"default_asset_symbol"`
	DefaultAssetDecimals int    `yaml:"default_asset_decimals"`
	DefaultPayTo         string `yaml:"default_pay_to"`
}

// LoggerConfig defines logging parameters.
type LoggerConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig defines observability endpoints.
type MetricsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"path"`
	HealthPath string `yaml:"health_path"`
	ReadyPath  string `yaml:"ready_path"`
}

// RouteDefinition represents an individual static route for bootstrap mode.
type RouteDefinition struct {
	RouteID               string            `yaml:"route_id"`
	Path                  string            `yaml:"path"`
	Upstream              string            `yaml:"upstream"`
	PriceBaseUnits        int64             `yaml:"price_base_units"`
	Asset                 string            `yaml:"asset"`
	Network               string            `yaml:"network"`
	PayeeAddress          string            `yaml:"payee_address"`
	AllowedPaymentMethods string            `yaml:"allowed_payment_methods"`
	TimeoutSeconds        float64           `yaml:"timeout_seconds"`
	RateLimitRPM          int               `yaml:"rate_limit_rpm"`
	Methods               []string          `yaml:"methods"`
	UpstreamHeaders       map[string]string `yaml:"upstream_headers"`
	MaxBodyBytes          int64             `yaml:"max_body_bytes"`
}

// AuthConfig defines control plane and administrative API authentication settings.
type AuthConfig struct {
	JWTSecret                  string         `yaml:"jwt_secret"`
	TokenDurationHours         int            `yaml:"token_duration_hours"`
	UpstreamMasterKey          string         `yaml:"upstream_master_key"`
	UpstreamMasterKeyVersion   int            `yaml:"upstream_master_key_version"`
	UpstreamPreviousMasterKeys map[int]string `yaml:"upstream_previous_master_keys"`
}

// GatewayConfig is the root configuration object for the Go Gateway.
type GatewayConfig struct {
	Version     string            `yaml:"version"`
	Server      ServerConfig      `yaml:"server"`
	Auth        AuthConfig        `yaml:"auth"`
	Database    DatabaseConfig    `yaml:"database"`
	Facilitator FacilitatorConfig `yaml:"facilitator"`
	Settlement  SettlementConfig  `yaml:"settlement"`
	Logger      LoggerConfig      `yaml:"logger"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Routes      []RouteDefinition `yaml:"routes"`
}

// DefaultConfig returns safe, production-grade defaults.
// SECURITY-REVIEW: PostgresURL defaults to empty so standalone/unit tests never
// implicitly connect to or mutate a developer's local PostgreSQL database (P1-2).
func DefaultConfig() GatewayConfig {
	return GatewayConfig{
		Version: "2.0.0",
		Server: ServerConfig{
			Host:                   "0.0.0.0",
			Port:                   8000,
			ReadTimeoutSeconds:     15.0,
			WriteTimeoutSeconds:    30.0,
			IdleTimeoutSeconds:     60.0,
			ShutdownTimeoutSeconds: 10.0,
		},
		Auth: AuthConfig{
			TokenDurationHours:       24,
			UpstreamMasterKeyVersion: 1,
		},
		Database: DatabaseConfig{
			PostgresURL:            "",
			MaxOpenConns:           25,
			MaxIdleConns:           10,
			ConnMaxLifetimeSeconds: 300,
		},
		Facilitator: FacilitatorConfig{
			URL:            "http://127.0.0.1:8001",
			TimeoutSeconds: 5.0,
		},
		Settlement: SettlementConfig{
			DefaultNetwork:       "eip155:84532",
			DefaultAsset:         "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
			DefaultAssetSymbol:   "USDC",
			DefaultAssetDecimals: 6,
			DefaultPayTo:         "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
		Logger: LoggerConfig{
			Level:  "info",
			Format: "json",
		},
		Metrics: MetricsConfig{
			Enabled:    true,
			Path:       "/metrics",
			HealthPath: "/healthz",
			ReadyPath:  "/readyz",
		},
		Routes: []RouteDefinition{},
	}
}

// Load loads configuration from a YAML file path with environment variable overrides.
func Load(path string) (*GatewayConfig, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config YAML: %w", err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides injects environment variables if defined.
func applyEnvOverrides(cfg *GatewayConfig) {
	if host := os.Getenv("AGENTPAY_HOST"); host != "" {
		cfg.Server.Host = host
	}
	if portStr := os.Getenv("AGENTPAY_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.Server.Port = p
		}
	}
	if pgURL := os.Getenv("AGENTPAY_POSTGRES_URL"); pgURL != "" {
		cfg.Database.PostgresURL = pgURL
	}
	if facURL := os.Getenv("AGENTPAY_FACILITATOR_URL"); facURL != "" {
		cfg.Facilitator.URL = facURL
	}
	if facKey := os.Getenv("AGENTPAY_FACILITATOR_API_KEY"); facKey != "" {
		cfg.Facilitator.APIKey = facKey
	}
	if logLevel := os.Getenv("AGENTPAY_LOG_LEVEL"); logLevel != "" {
		cfg.Logger.Level = logLevel
	}
	if logFmt := os.Getenv("AGENTPAY_LOG_FORMAT"); logFmt != "" {
		cfg.Logger.Format = logFmt
	}
	if jwtSecret := os.Getenv("AGENTPAY_JWT_SECRET"); jwtSecret != "" {
		cfg.Auth.JWTSecret = jwtSecret
	}
	if masterKey := os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY"); masterKey != "" {
		cfg.Auth.UpstreamMasterKey = masterKey
	}
	if keyVerStr := os.Getenv("AGENTPAY_UPSTREAM_MASTER_KEY_VERSION"); keyVerStr != "" {
		if v, err := strconv.Atoi(keyVerStr); err == nil && v > 0 {
			cfg.Auth.UpstreamMasterKeyVersion = v
		}
	}
}

// Validate verifies config bounds and mandatory fields.
func Validate(cfg *GatewayConfig) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535, got %d", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeoutSeconds <= 0 {
		return fmt.Errorf("server read_timeout_seconds must be > 0")
	}
	if cfg.Server.WriteTimeoutSeconds <= 0 {
		return fmt.Errorf("server write_timeout_seconds must be > 0")
	}
	if cfg.Server.ShutdownTimeoutSeconds <= 0 {
		return fmt.Errorf("server shutdown_timeout_seconds must be > 0")
	}
	lvl := strings.ToLower(cfg.Logger.Level)
	if lvl != "debug" && lvl != "info" && lvl != "warn" && lvl != "error" {
		return fmt.Errorf("unsupported logger level: %s", cfg.Logger.Level)
	}
	fmtLower := strings.ToLower(cfg.Logger.Format)
	if fmtLower != "json" && fmtLower != "text" {
		return fmt.Errorf("unsupported logger format: %s", cfg.Logger.Format)
	}

	// Validate routes if specified
	for i, r := range cfg.Routes {
		if r.Path == "" {
			return fmt.Errorf("route [%d] path cannot be empty", i)
		}
		if r.Upstream == "" {
			return fmt.Errorf("route [%d] upstream cannot be empty", i)
		}
		if r.PriceBaseUnits < 0 {
			return fmt.Errorf("route [%d] price_base_units cannot be negative", i)
		}
	}

	return nil
}

// ReadTimeout returns Duration for http.Server.ReadTimeout.
func (s ServerConfig) ReadTimeout() time.Duration {
	return time.Duration(s.ReadTimeoutSeconds * float64(time.Second))
}

// WriteTimeout returns Duration for http.Server.WriteTimeout.
func (s ServerConfig) WriteTimeout() time.Duration {
	return time.Duration(s.WriteTimeoutSeconds * float64(time.Second))
}

// IdleTimeout returns Duration for http.Server.IdleTimeout.
func (s ServerConfig) IdleTimeout() time.Duration {
	return time.Duration(s.IdleTimeoutSeconds * float64(time.Second))
}

// ShutdownTimeout returns Duration for graceful shutdown context.
func (s ServerConfig) ShutdownTimeout() time.Duration {
	return time.Duration(s.ShutdownTimeoutSeconds * float64(time.Second))
}
