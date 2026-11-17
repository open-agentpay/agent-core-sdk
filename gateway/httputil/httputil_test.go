package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]string{"status": "ok"})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("unexpected content type: %s", rec.Header().Get("Content-Type"))
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "INVALID_INPUT", "missing field")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var resp StandardErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode error body: %v", err)
	}
	if resp.Error.Code != "INVALID_INPUT" || resp.Error.Message != "missing field" {
		t.Fatalf("unexpected error response: %+v", resp)
	}
}

func TestParsePagination(t *testing.T) {
	q := url.Values{}
	q.Set("limit", "25")
	q.Set("offset", "10")

	limit, offset := ParsePagination(q, 50, 100)
	if limit != 25 || offset != 10 {
		t.Fatalf("expected 25, 10; got %d, %d", limit, offset)
	}

	// Default & max limit
	q2 := url.Values{}
	q2.Set("limit", "9999")
	limit2, offset2 := ParsePagination(q2, 50, 200)
	if limit2 != 200 || offset2 != 0 {
		t.Fatalf("expected 200, 0; got %d, %d", limit2, offset2)
	}
}

func TestHopByHopHeaders(t *testing.T) {
	if !IsHopByHopHeader("Connection") {
		t.Error("expected Connection to be hop-by-hop")
	}
	if !IsHopByHopHeader("transfer-encoding") {
		t.Error("expected transfer-encoding to be hop-by-hop")
	}
	if IsHopByHopHeader("Content-Type") {
		t.Error("Content-Type should not be hop-by-hop")
	}

	src := http.Header{}
	src.Set("Connection", "close")
	src.Set("Content-Type", "application/json")
	src.Set("X-Custom", "value")

	dst := http.Header{}
	CopyHeaders(dst, src, "X-Custom")

	if dst.Get("Connection") != "" {
		t.Error("Connection header should have been skipped")
	}
	if dst.Get("X-Custom") != "" {
		t.Error("X-Custom header should have been skipped")
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should have been copied")
	}
}
