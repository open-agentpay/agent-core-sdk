package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	if err := Validate(&cfg); err != nil {
		t.Fatalf("DefaultConfig should be valid, got: %v", err)
	}
	if cfg.Server.Port != 8000 {
		t.Errorf("expected default port 8000, got %d", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout() <= 0 {
		t.Errorf("expected positive read timeout")
	}
}

func TestLoadConfigFileAndEnvOverrides(t *testing.T) {
	tempDir := t.TempDir()
	yamlPath := filepath.Join(tempDir, "gateway.yaml")

	content := `
version: "2.0.0"
server:
  host: "127.0.0.1"
  port: 9000
  read_timeout_seconds: 5.0
  write_timeout_seconds: 10.0
  shutdown_timeout_seconds: 3.0
logger:
  level: "debug"
  format: "text"
routes:
  - route_id: "rou_1"
    path: "/v1/test"
    upstream: "https://httpbin.org/get"
    price_base_units: 5000
`
	if err := os.WriteFile(yamlPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	// Set environment override
	os.Setenv("AGENTPAY_PORT", "9090")
	defer os.Unsetenv("AGENTPAY_PORT")

	cfg, err := Load(yamlPath)
	if err != nil {
		t.Fatalf("failed to load valid config: %v", err)
	}

	// Env variable must override file value
	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090 (from env), got %d", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Server.Host)
	}
	if cfg.Logger.Level != "debug" {
		t.Errorf("expected debug log level, got %s", cfg.Logger.Level)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].PriceBaseUnits != 5000 {
		t.Errorf("expected price 5000, got %d", cfg.Routes[0].PriceBaseUnits)
	}
}

func TestValidateRejectsInvalidBounds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Port = 99999
	if err := Validate(&cfg); err == nil {
		t.Errorf("expected error for port 99999, got nil")
	}

	cfg = DefaultConfig()
	cfg.Logger.Level = "invalid_level"
	if err := Validate(&cfg); err == nil {
		t.Errorf("expected error for invalid logger level, got nil")
	}

	cfg = DefaultConfig()
	cfg.Routes = []RouteDefinition{
		{Path: "/test", Upstream: "", PriceBaseUnits: 10},
	}
	if err := Validate(&cfg); err == nil {
		t.Errorf("expected error for empty upstream, got nil")
	}
}
