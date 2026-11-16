package proxy

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreamSniffer_NormalStream(t *testing.T) {
	upstreamSSE := `data: {"id":"c1","choices":[{"delta":{"content":"Hello"}}]}

data: {"id":"c2","choices":[{"delta":{"content":" world"}}]}

data: {"id":"c3","choices":[{"delta":{}}],"usage":{"prompt_tokens":10,"completion_tokens":25,"total_tokens":35}}

data: [DONE]

`
	reader := io.NopCloser(strings.NewReader(upstreamSSE))
	rec := httptest.NewRecorder()

	sniffer := NewStreamSniffer(SniffOptions{
		PromptPriceBaseUnits:     2000, // 2000 base units per 1k prompt
		CompletionPriceBaseUnits: 8000, // 8000 base units per 1k completion
		EstimatedPromptTokens:    10,
		MaxAllowedBudget:         1000000, // generous budget
	})

	res, err := sniffer.SniffAndForward(rec, reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.TerminatedEarly {
		t.Fatalf("expected not terminated early, got terminated")
	}
	if res.CompletionTokens != 25 {
		t.Fatalf("expected 25 completion tokens, got %d", res.CompletionTokens)
	}
	if res.PromptTokens != 10 {
		t.Fatalf("expected 10 prompt tokens, got %d", res.PromptTokens)
	}

	// Cost: 10 * 2000 / 1000 + 25 * 8000 / 1000 = 20 + 200 = 220 base units
	expectedCost := int64(220)
	if res.TotalCost != expectedCost {
		t.Fatalf("expected total cost %d, got %d", expectedCost, res.TotalCost)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Hello") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("expected downstream body to contain forwarded chunks, got: %s", body)
	}
}

func TestStreamSniffer_MidStreamBudgetBreaker(t *testing.T) {
	// A long stream that should be terminated early
	chunks := []string{
		`data: {"choices":[{"delta":{"content":"A"}}]}`,
		`data: {"choices":[{"delta":{"content":"B"}}]}`,
		`data: {"choices":[{"delta":{"content":"C"}}]}`,
		`data: {"choices":[{"delta":{"content":"D"}}]}`,
		`data: {"choices":[{"delta":{"content":"E"}}]}`,
		`data: [DONE]`,
	}
	upstreamSSE := strings.Join(chunks, "\n\n") + "\n\n"
	reader := io.NopCloser(strings.NewReader(upstreamSSE))
	rec := httptest.NewRecorder()

	// Budget only allows 2 completion tokens
	// Prompt cost: 10 * 2000 / 1000 = 20 base units
	// Completion price: 8000 base units / 1k = 8 base units per token
	// Max budget: 20 + 2 * 8 = 36 base units
	budgetBroken := false
	sniffer := NewStreamSniffer(SniffOptions{
		PromptPriceBaseUnits:     2000,
		CompletionPriceBaseUnits: 8000,
		EstimatedPromptTokens:    10,
		MaxAllowedBudget:         36, // breaks after 2 completion tokens
		OnBudgetExceeded: func(cost int64) {
			budgetBroken = true
		},
	})

	res, err := sniffer.SniffAndForward(rec, reader)
	if err != ErrBudgetExhausted {
		t.Fatalf("expected ErrBudgetExhausted, got %v", err)
	}
	if !res.TerminatedEarly {
		t.Fatalf("expected TerminatedEarly to be true")
	}
	if !budgetBroken {
		t.Fatalf("expected OnBudgetExceeded callback to be invoked")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "STREAM_BUDGET_EXHAUSTED") {
		t.Fatalf("expected body to contain STREAM_BUDGET_EXHAUSTED error frame, got: %s", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("expected stream to be cut off before [DONE]")
	}
}
