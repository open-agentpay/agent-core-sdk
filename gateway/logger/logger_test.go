package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestStructuredLoggerRedactionAndContext(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "debug", Format: "json"}
	log := InitGlobalLogger(cfg, &buf)

	ctx := WithContext(context.Background(), "req_123456", "ten_test", "prj_test")
	log.InfoContext(ctx, "inbound request processed",
		slog.String("api_key", "agp_live_secretkey12345"),
		slog.String("authorization", "Bearer abcdef"),
		slog.String("client_ip", "192.0.2.1"),
		slog.Int("status", 200),
	)

	output := buf.String()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("failed to parse JSON log output: %v, raw: %s", err, output)
	}

	// Verify contextual tags injected from context
	if parsed["request_id"] != "req_123456" {
		t.Errorf("expected request_id 'req_123456', got '%v'", parsed["request_id"])
	}
	if parsed["tenant_id"] != "ten_test" {
		t.Errorf("expected tenant_id 'ten_test', got '%v'", parsed["tenant_id"])
	}
	if parsed["service"] != "agentpay-gateway" {
		t.Errorf("expected service 'agentpay-gateway', got '%v'", parsed["service"])
	}

	// Verify sensitive attributes redacted
	if parsed["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be redacted, got '%v'", parsed["api_key"])
	}
	if parsed["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization to be redacted, got '%v'", parsed["authorization"])
	}

	// Non-sensitive fields preserved
	if parsed["client_ip"] != "192.0.2.1" {
		t.Errorf("expected client_ip '192.0.2.1', got '%v'", parsed["client_ip"])
	}
}
