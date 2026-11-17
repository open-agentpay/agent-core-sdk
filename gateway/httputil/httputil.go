// Package httputil provides shared HTTP helpers, standardized JSON formatting,
// pagination parsing, and hop-by-hop header management across gateway handlers.
package httputil

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// StandardErrorResponse represents the unified error payload returned by gateway APIs.
type StandardErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes an individual API error.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteJSON serializes data as JSON and writes it with the provided HTTP status code.
func WriteJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteError writes a standardized JSON error response.
func WriteError(w http.ResponseWriter, statusCode int, code, message string) {
	WriteJSON(w, statusCode, StandardErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// ParsePagination extracts and normalizes "limit" and "offset" query parameters.
func ParsePagination(q url.Values, defaultLimit, maxLimit int) (limit, offset int) {
	if defaultLimit <= 0 {
		defaultLimit = 50
	}
	if maxLimit <= 0 {
		maxLimit = 500
	}

	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	offset, err = strconv.Atoi(q.Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}

	return limit, offset
}

// hopByHopHeaders defines headers that are hop-by-hop per RFC 7230 Section 6.1.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// IsHopByHopHeader returns true if the specified header name is a hop-by-hop header.
func IsHopByHopHeader(h string) bool {
	return hopByHopHeaders[strings.ToLower(strings.TrimSpace(h))]
}

// CopyHeaders copies all allowed headers from src to dst, skipping hop-by-hop headers.
func CopyHeaders(dst, src http.Header, skipHeaders ...string) {
	skipMap := make(map[string]bool, len(skipHeaders))
	for _, s := range skipHeaders {
		skipMap[strings.ToLower(strings.TrimSpace(s))] = true
	}

	for k, vv := range src {
		lowerK := strings.ToLower(k)
		if IsHopByHopHeader(k) || skipMap[lowerK] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
