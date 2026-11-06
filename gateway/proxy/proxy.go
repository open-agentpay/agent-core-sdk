// Package proxy implements high-throughput, secure HTTP reverse proxying for AgentPay Go Gateway (T2.2).
// It manages upstream forwarding, hop-by-hop and spoofed header sanitization, credential isolation,
// request body limits, and robust timeout handling.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/metrics"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
	"github.com/open-agentpay/agent-core-sdk/gateway/upstreamauth"
)

var pathPlaceholderRegex = regexp.MustCompile(`\{([a-zA-Z0-9_.\-]+)\}`)

type errReadCloser struct {
	err error
}

func (e *errReadCloser) Read(_ []byte) (int, error) { return 0, e.err }
func (e *errReadCloser) Close() error               { return nil }

const (
	DefaultMaxBodyBytes = 10 * 1024 * 1024 // 10 MB
	DefaultTimeout      = 15 * time.Second
)

// Hop-by-hop headers to strip per RFC 7230 Section 6.1
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// PaymentContext represents verified identity and payment metadata to inject upstream.
type PaymentContext struct {
	PayerAddress        string
	AmountBaseUnits     int64
	Asset               string
	Network             string
	TxHash              string
	IdempotencyKey      string
	RequestID           string
	ConfigVersion       string
	ConfigHash          string
	AgentID             string
	TenantID            string
	ProjectID           string
	DeclaredSessionID   string
	DeclaredTaskID      string
	DeclaredToolName    string
	DeclaredParentReqID string
}

// Handler forwards requests to configured upstreams with security boundary protection.
type Handler struct {
	transport http.RoundTripper
	metrics   *metrics.Metrics
}

// NewHandler creates a reverse proxy handler with an optimized Transport pool.
// # SECURITY-REVIEW
func NewHandler(m *metrics.Metrics, transport http.RoundTripper) *Handler {
	if transport == nil {
		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           upstreamauth.SafeDialContext(dialer),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}
	if m == nil {
		m = metrics.New()
	}
	return &Handler{
		transport: transport,
		metrics:   m,
	}
}

// Forward executes the reverse proxy dispatch against the target route.
func (h *Handler) Forward(w http.ResponseWriter, r *http.Request, route *rcu.RouteConfig, pCtx *PaymentContext) {
	// 1. Validate HTTP Method if route restricts methods
	if len(route.Methods) > 0 {
		methodAllowed := false
		for _, m := range route.Methods {
			if strings.EqualFold(m, r.Method) {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			writeProxyError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
				fmt.Sprintf("HTTP method %s is not permitted for route %s", r.Method, route.RouteID))
			return
		}
	}

	// 2. Enforce Request Body Size Limit
	maxBody := route.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// 3. Resolve and parse Upstream Target URL
	targetURL, err := url.Parse(route.UpstreamURL)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		slog.Error("malformed upstream URL for route",
			slog.String("route_id", route.RouteID),
			slog.String("upstream_url", route.UpstreamURL),
			slog.Any("error", err),
		)
		h.metrics.IncUpstreamErrors()
		writeProxyError(w, http.StatusBadGateway, "INVALID_UPSTREAM_CONFIG", "upstream target is invalid")
		return
	}

	// 3b. Extract optional JSON body parameters if route or upstream URL uses {param} templates
	var bodyParams map[string]interface{}
	if (rcu.HasPathTemplate(route.UpstreamURL) || rcu.HasPathTemplate(route.PathPattern)) && r.Body != nil {
		bodyBytes, errRead := io.ReadAll(r.Body)
		if errRead == nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if len(bodyBytes) > 0 {
				_ = json.Unmarshal(bodyBytes, &bodyParams)
			}
		} else {
			r.Body = &errReadCloser{err: errRead}
		}
	}

	// 4. Configure per-route timeout context
	timeout := DefaultTimeout
	if route.TimeoutMS > 0 {
		timeout = time.Duration(route.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// 5. Construct httputil.ReverseProxy with Director & ErrorHandler
	proxy := &httputil.ReverseProxy{
		Transport: h.transport,
		Director: func(outReq *http.Request) {
			// Rewrite target URL
			outReq.URL.Scheme = targetURL.Scheme
			outReq.URL.Host = targetURL.Host

			// Path mapping: resolve {param} templates, /* wildcards, or static paths
			targetPath := targetURL.Path
			reqPath := r.URL.Path
			resolvedParams, consumedQueryKeys := resolveTemplateParams(route, r, targetPath, bodyParams)

			if rcu.HasPathTemplate(targetPath) {
				outReq.URL.Path = replacePathPlaceholders(targetPath, resolvedParams)
			} else if rcu.HasPathTemplate(route.PathPattern) {
				effectiveReqPath := reqPath
				prefix := rcu.TemplateStaticPrefix(route.PathPattern)
				if rcu.HasPathTemplate(reqPath) || !strings.HasPrefix(reqPath, prefix+"/") {
					effectiveReqPath = replacePathPlaceholders(route.PathPattern, resolvedParams)
				}
				suffix := strings.TrimPrefix(effectiveReqPath, prefix)
				if targetPath == "" || targetPath == "/" {
					outReq.URL.Path = suffix
				} else {
					outReq.URL.Path = singleJoiningSlash(targetPath, suffix)
				}
			} else if strings.HasSuffix(route.PathPattern, "/*") {
				prefix := strings.TrimSuffix(route.PathPattern, "/*")
				suffix := strings.TrimPrefix(reqPath, prefix)
				if targetPath == "" || targetPath == "/" {
					outReq.URL.Path = suffix
				} else {
					outReq.URL.Path = singleJoiningSlash(targetPath, suffix)
				}
			} else if route.PathPattern != "" && route.PathPattern == reqPath && targetPath != "" && targetPath != "/" {
				outReq.URL.Path = targetPath
			} else {
				if targetPath == "" || targetPath == "/" {
					outReq.URL.Path = reqPath
				} else {
					outReq.URL.Path = singleJoiningSlash(targetPath, reqPath)
				}
			}
			// Reset RawPath so net/http encodes the rewritten Path cleanly without stale %7Bparam%7D escapes
			outReq.URL.RawPath = ""

			// Merge upstream target query and incoming request query parameters
			targetQuery := replaceQueryPlaceholders(targetURL.RawQuery, resolvedParams)
			reqQuery := r.URL.RawQuery
			if len(consumedQueryKeys) > 0 && reqQuery != "" {
				if reqVals, errQ := url.ParseQuery(reqQuery); errQ == nil {
					for k := range consumedQueryKeys {
						reqVals.Del(k)
					}
					reqQuery = reqVals.Encode()
				}
			}
			if targetQuery == "" {
				outReq.URL.RawQuery = reqQuery
			} else if reqQuery == "" {
				outReq.URL.RawQuery = targetQuery
			} else {
				targetValues, errT := url.ParseQuery(targetQuery)
				reqValues, errR := url.ParseQuery(reqQuery)
				if errT == nil && errR == nil {
					for k, vs := range reqValues {
						for _, v := range vs {
							targetValues.Add(k, v)
						}
					}
					outReq.URL.RawQuery = targetValues.Encode()
				} else {
					outReq.URL.RawQuery = targetQuery + "&" + reqQuery
				}
			}
			outReq.Host = targetURL.Host

			// Sanitize incoming headers: strip Hop-by-Hop & untrusted client identity headers
			sanitizeHeaders(outReq.Header)

			// Inject Forwarded headers
			clientIP := extractClientIP(r)
			if prior, ok := outReq.Header["X-Forwarded-For"]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			outReq.Header.Set("X-Forwarded-For", clientIP)
			outReq.Header.Set("X-Forwarded-Proto", extractScheme(r))
			outReq.Header.Set("X-Forwarded-Host", r.Host)

			// Inject verified Payment Context if authenticated
			if pCtx != nil {
				if pCtx.RequestID != "" {
					outReq.Header.Set("X-Request-ID", pCtx.RequestID)
				}
				if pCtx.PayerAddress != "" {
					outReq.Header.Set("X-Payer-Address", pCtx.PayerAddress)
				}
				if pCtx.AmountBaseUnits > 0 {
					outReq.Header.Set("X-Payment-Amount", fmt.Sprintf("%d", pCtx.AmountBaseUnits))
				}
				if pCtx.Asset != "" {
					outReq.Header.Set("X-Payment-Asset", pCtx.Asset)
				}
				if pCtx.Network != "" {
					outReq.Header.Set("X-Payment-Network", pCtx.Network)
				}
				if pCtx.TxHash != "" {
					outReq.Header.Set("X-Payment-Tx-Hash", pCtx.TxHash)
				}
				if pCtx.IdempotencyKey != "" {
					outReq.Header.Set("X-Payment-Idempotency-Key", pCtx.IdempotencyKey)
				}
				if pCtx.ConfigVersion != "" {
					outReq.Header.Set("X-AgentPay-Config-Version", pCtx.ConfigVersion)
				}
				if pCtx.ConfigHash != "" {
					outReq.Header.Set("X-AgentPay-Config-Hash", pCtx.ConfigHash)
				}
				if pCtx.AgentID != "" {
					outReq.Header.Set("X-Agent-ID", pCtx.AgentID)
				}
				if pCtx.TenantID != "" {
					outReq.Header.Set("X-Tenant-ID", pCtx.TenantID)
				}
				if pCtx.ProjectID != "" {
					outReq.Header.Set("X-Project-ID", pCtx.ProjectID)
				}
				if pCtx.DeclaredSessionID != "" {
					outReq.Header.Set("X-Session-ID", pCtx.DeclaredSessionID)
				}
				if pCtx.DeclaredTaskID != "" {
					outReq.Header.Set("X-Task-ID", pCtx.DeclaredTaskID)
				}
				if pCtx.DeclaredToolName != "" {
					outReq.Header.Set("X-Tool-Name", pCtx.DeclaredToolName)
				}
			}

			// Inject isolated upstream credentials configured for this route (e.g. backend tokens)
			for k, v := range route.UpstreamHeaders {
				outReq.Header.Set(k, v)
			}

			// Apply configured upstream authentication strategy (T4.2 upstream auth)
			if route.UpstreamAuth != nil && route.UpstreamAuth.Type != "" && route.UpstreamAuth.Type != "none" {
				if auth, ok := upstreamauth.Get(route.UpstreamAuth.Type); ok {
					secrets := route.UpstreamSecrets
					if secrets == nil && len(route.UpstreamAuth.SecretEnc) > 0 {
						decrypted, err := upstreamauth.DecryptSecretsVersioned(route.UpstreamAuth.SecretEnc, route.UpstreamAuth.KeyVersion)
						if err == nil {
							secrets = decrypted
						}
					}
					if len(secrets) == 0 && route.UpstreamAuth != nil && len(route.UpstreamAuth.Secrets) > 0 {
						secrets = route.UpstreamAuth.Secrets
					}
					if err := auth.Apply(outReq.Context(), outReq, route.UpstreamAuth.Params, secrets); err != nil {
						slog.Error("failed to apply upstream authentication",
							slog.String("route_id", route.RouteID),
							slog.String("auth_type", route.UpstreamAuth.Type),
							slog.Any("error", err),
						)
					}
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Strip hop-by-hop headers from upstream response
			for _, h := range hopByHopHeaders {
				resp.Header.Del(h)
			}
			// Prevent sensitive upstream server info leaks
			resp.Header.Del("Server")
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			h.metrics.IncUpstreamErrors()

			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeProxyError(rw, http.StatusRequestEntityTooLarge, "REQUEST_ENTITY_TOO_LARGE",
					fmt.Sprintf("request body exceeds maximum limit of %d bytes", maxBytesErr.Limit))
				return
			}

			if errors.Is(err, context.DeadlineExceeded) {
				slog.Warn("upstream request timed out",
					slog.String("route_id", route.RouteID),
					slog.Duration("timeout", timeout),
				)
				writeProxyError(rw, http.StatusGatewayTimeout, "UPSTREAM_TIMEOUT",
					fmt.Sprintf("upstream service timed out after %v", timeout))
				return
			}

			slog.Error("upstream connection failed",
				slog.String("route_id", route.RouteID),
				slog.String("upstream_url", route.UpstreamURL),
				slog.Any("error", err),
			)
			writeProxyError(rw, http.StatusBadGateway, "BAD_GATEWAY", "failed to connect to upstream service")
		},
	}

	// Serve the proxied request under the timeout context
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

// sanitizeHeaders removes Hop-by-Hop headers and client-spoofed identity headers.
func sanitizeHeaders(hdr http.Header) {
	// Strip standard hop-by-hop headers
	for _, h := range hopByHopHeaders {
		hdr.Del(h)
	}

	// Strip client-supplied security headers matching untrusted prefixes or agent identity
	for k := range hdr {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "x-payer-") ||
			strings.HasPrefix(lower, "x-payment-") ||
			strings.HasPrefix(lower, "x-agentpay-") ||
			lower == "x-agent-id" ||
			lower == "x-agent-tenant-id" ||
			lower == "x-agent-project-id" {
			hdr.Del(k)
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// resolveTemplateParams extracts `{param}` values for route and upstream URL templates.
// Priority order:
//  1. URL Path parameters extracted via route.PathPattern (or /* suffix if upstream has a single {param})
//  2. Incoming URL Query parameters (marking matched query keys as consumed so they aren't duplicated)
//  3. JSON Request Body top-level fields
func resolveTemplateParams(
	route *rcu.RouteConfig,
	r *http.Request,
	targetPath string,
	bodyParams map[string]interface{},
) (map[string]string, map[string]bool) {
	resolved := make(map[string]string)
	fromPath := make(map[string]bool)
	consumedQuery := make(map[string]bool)

	if !rcu.HasPathTemplate(route.UpstreamURL) && !rcu.HasPathTemplate(route.PathPattern) {
		return resolved, consumedQuery
	}

	// 1. Extract from URL path template if route.PathPattern has {param}
	if rcu.HasPathTemplate(route.PathPattern) {
		if pathParams, ok := rcu.ExtractPathParams(route.PathPattern, r.URL.Path); ok {
			for k, v := range pathParams {
				if v != "" {
					resolved[k] = v
					fromPath[k] = true
				}
			}
		}
	}

	// 1b. If route uses /* wildcard and targetPath has a single {param}, map the wildcard suffix to {param}
	if strings.HasSuffix(route.PathPattern, "/*") && rcu.HasPathTemplate(targetPath) {
		prefix := strings.TrimSuffix(route.PathPattern, "/*")
		suffix := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
		if suffix != "" {
			matches := pathPlaceholderRegex.FindAllStringSubmatch(targetPath, -1)
			if len(matches) == 1 {
				paramName := matches[0][1]
				resolved[paramName] = suffix
				fromPath[paramName] = true
			}
		}
	}

	// Collect all placeholder names referenced in UpstreamURL or PathPattern
	paramNames := make(map[string]bool)
	for _, m := range pathPlaceholderRegex.FindAllStringSubmatch(route.UpstreamURL, -1) {
		paramNames[m[1]] = true
	}
	for _, m := range pathPlaceholderRegex.FindAllStringSubmatch(route.PathPattern, -1) {
		paramNames[m[1]] = true
	}

	queryVals := r.URL.Query()
	for name := range paramNames {
		if fromPath[name] {
			continue
		}
		// 2. Fallback to Query parameters
		if val := queryVals.Get(name); val != "" {
			resolved[name] = val
			consumedQuery[name] = true
			continue
		}
		foundInQuery := false
		for qk, qvs := range queryVals {
			if strings.EqualFold(qk, name) && len(qvs) > 0 && qvs[0] != "" {
				resolved[name] = qvs[0]
				consumedQuery[qk] = true
				foundInQuery = true
				break
			}
		}
		if foundInQuery {
			continue
		}

		// 3. Fallback to JSON Body fields
		if len(bodyParams) > 0 {
			if bv, ok := bodyParams[name]; ok && bv != nil {
				if s := formatScalarParam(bv); s != "" {
					resolved[name] = s
					continue
				}
			}
			for bk, bv := range bodyParams {
				if strings.EqualFold(bk, name) && bv != nil {
					if s := formatScalarParam(bv); s != "" {
						resolved[name] = s
						break
					}
				}
			}
		}
	}

	return resolved, consumedQuery
}

func formatScalarParam(v interface{}) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64, bool, int, int64, json.Number:
		return fmt.Sprintf("%v", val)
	case []interface{}:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			if s := formatScalarParam(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func replacePathPlaceholders(pathTemplate string, params map[string]string) string {
	if len(params) == 0 || !rcu.HasPathTemplate(pathTemplate) {
		return pathTemplate
	}
	return pathPlaceholderRegex.ReplaceAllStringFunc(pathTemplate, func(match string) string {
		name := match[1 : len(match)-1]
		if val, ok := params[name]; ok && val != "" {
			return val
		}
		return match
	})
}

func replaceQueryPlaceholders(rawQuery string, params map[string]string) string {
	if len(params) == 0 || rawQuery == "" {
		return rawQuery
	}
	res := rawQuery
	for k, v := range params {
		if v == "" {
			continue
		}
		escaped := url.QueryEscape(v)
		res = strings.ReplaceAll(res, "{"+k+"}", escaped)
		res = strings.ReplaceAll(res, "%7B"+k+"%7D", escaped)
		res = strings.ReplaceAll(res, "%7b"+k+"%7d", escaped)
	}
	return res
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func extractScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func writeProxyError(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   errorCode,
		"message": message,
	})
}

// ProxyResponse captures the upstream execution status, headers, and buffered body.
type ProxyResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// CaptureResponseWriter intercepts and buffers downstream response status and body while streaming.
type CaptureResponseWriter struct {
	http.ResponseWriter
	StatusCode  int
	Body        bytes.Buffer
	maxCapture  int
	wroteHeader bool
}

// NewCaptureResponseWriter creates a ResponseWriter that captures response status code and data.
func NewCaptureResponseWriter(w http.ResponseWriter, maxCapture int) *CaptureResponseWriter {
	if maxCapture <= 0 {
		maxCapture = 2 * 1024 * 1024 // 2 MB default capture buffer
	}
	return &CaptureResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK, // Default to 200 if WriteHeader not explicitly called before Write
		maxCapture:     maxCapture,
	}
}

func (c *CaptureResponseWriter) WriteHeader(code int) {
	if !c.wroteHeader {
		c.StatusCode = code
		c.wroteHeader = true
		c.ResponseWriter.WriteHeader(code)
	}
}

func (c *CaptureResponseWriter) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if c.Body.Len() < c.maxCapture {
		remaining := c.maxCapture - c.Body.Len()
		if len(b) > remaining {
			c.Body.Write(b[:remaining])
		} else {
			c.Body.Write(b)
		}
	}
	return c.ResponseWriter.Write(b)
}

func (c *CaptureResponseWriter) Flush() {
	if flusher, ok := c.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// ForwardWithCapture dispatches the request to upstream while recording the status code and response body.
func (h *Handler) ForwardWithCapture(w http.ResponseWriter, r *http.Request, route *rcu.RouteConfig, pCtx *PaymentContext) (*ProxyResponse, error) {
	cw := NewCaptureResponseWriter(w, 2*1024*1024)
	h.Forward(cw, r, route, pCtx)

	headers := make(map[string]string)
	for k := range cw.Header() {
		headers[k] = cw.Header().Get(k)
	}

	return &ProxyResponse{
		StatusCode: cw.StatusCode,
		Headers:    headers,
		Body:       cw.Body.Bytes(),
	}, nil
}
