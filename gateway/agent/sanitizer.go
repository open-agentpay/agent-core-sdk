package agent

import (
	"net"
	"net/http"
	"strings"
)

const (
	MaxDeclaredFieldLength = 128
)

// SanitizeDeclaredField cleanses an untrusted, self-reported client string.
// Enforces:
// 1. Hard truncation to MaxDeclaredFieldLength (128 characters)
// 2. Character whitelist filtering to prevent log injection, CRLF injection, and XSS
func SanitizeDeclaredField(val string) string {
	val = strings.TrimSpace(val)
	if len(val) == 0 {
		return ""
	}

	// 1. Truncate to maximum permitted length
	if len(val) > MaxDeclaredFieldLength {
		val = val[:MaxDeclaredFieldLength]
	}

	// 2. Whitelist: allowed are alphanumeric, '-', '_', '.', ':', '/'
	var b strings.Builder
	b.Grow(len(val))
	for _, ch := range val {
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// ExtractDeclaredContext inspects HTTP headers for declared workflow context.
func ExtractDeclaredContext(r *http.Request) DeclaredContext {
	return DeclaredContext{
		SessionID:       SanitizeDeclaredField(r.Header.Get("X-Session-ID")),
		TaskID:          SanitizeDeclaredField(r.Header.Get("X-Task-ID")),
		ToolName:        SanitizeDeclaredField(r.Header.Get("X-Tool-Name")),
		ParentRequestID: SanitizeDeclaredField(r.Header.Get("X-Parent-Request-ID")),
	}
}

// SanitizeAndStripSpoofedAgentHeaders unconditionally purges client-supplied
// Agent identity headers from the incoming request.
// Security invariant: agent_id MUST be determined by API Key / credential resolution alone.
func SanitizeAndStripSpoofedAgentHeaders(hdr http.Header) {
	for k := range hdr {
		lower := strings.ToLower(k)
		if lower == "x-agent-id" ||
			lower == "x-agent-tenant-id" ||
			lower == "x-agent-project-id" {
			hdr.Del(k)
		}
	}
}

// ExtractClientIP extracts the nearest upstream client IP address.
func ExtractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
