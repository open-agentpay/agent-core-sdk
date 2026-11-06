// Package logger provides structured, high-performance logging for AgentPay Go Gateway
// using Go standard library's log/slog with security redaction and contextual tracing.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type contextKey string

const (
	RequestIDKey   contextKey = "request_id"
	TenantIDKey    contextKey = "tenant_id"
	ProjectIDKey   contextKey = "project_id"
	CorrelationKey contextKey = "correlation_id"
)

var defaultRedactedKeys = map[string]bool{
	"authorization": true,
	"api_key":       true,
	"apikey":        true,
	"key":           true,
	"secret":        true,
	"token":         true,
	"private_key":   true,
	"password":      true,
}

// Config controls logger initialization.
type Config struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

// RedactingHandler wraps an slog.Handler to redact sensitive keys.
type RedactingHandler struct {
	slog.Handler
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Extract tracing fields from context if present
	if reqID, ok := ctx.Value(RequestIDKey).(string); ok && reqID != "" {
		r.Add(slog.String("request_id", reqID))
	}
	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok && tenantID != "" {
		r.Add(slog.String("tenant_id", tenantID))
	}
	if projectID, ok := ctx.Value(ProjectIDKey).(string); ok && projectID != "" {
		r.Add(slog.String("project_id", projectID))
	}

	// Redact sensitive attributes in the record
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		newRecord.Add(redactAttr(a))
		return true
	})

	return h.Handler.Handle(ctx, newRecord)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &RedactingHandler{Handler: h.Handler.WithAttrs(redacted)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{Handler: h.Handler.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	keyLower := strings.ToLower(a.Key)
	if defaultRedactedKeys[keyLower] {
		return slog.String(a.Key, "[REDACTED]")
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		redacted := make([]slog.Attr, len(attrs))
		for i, attr := range attrs {
			redacted[i] = redactAttr(attr)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redacted...)}
	}
	return a
}

// InitGlobalLogger initializes and sets the default global slog logger.
func InitGlobalLogger(cfg Config, out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stdout
	}

	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var baseHandler slog.Handler
	if strings.ToLower(cfg.Format) == "text" {
		baseHandler = slog.NewTextHandler(out, opts)
	} else {
		baseHandler = slog.NewJSONHandler(out, opts)
	}

	handler := &RedactingHandler{Handler: baseHandler}
	logger := slog.New(handler).With(
		slog.String("service", "agentpay-gateway"),
	)

	slog.SetDefault(logger)
	return logger
}

// WithContext returns a new context with standard request tracing tags.
func WithContext(ctx context.Context, requestID, tenantID, projectID string) context.Context {
	ctx = context.WithValue(ctx, RequestIDKey, requestID)
	ctx = context.WithValue(ctx, TenantIDKey, tenantID)
	ctx = context.WithValue(ctx, ProjectIDKey, projectID)
	return ctx
}
