package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var ErrBudgetExhausted = errors.New("stream budget exhausted")

// SniffOptions configures the real-time SSE stream sniffer.
type SniffOptions struct {
	PromptPriceBaseUnits     int64 // per 1,000 prompt tokens
	CompletionPriceBaseUnits int64 // per 1,000 completion tokens
	EstimatedPromptTokens    int64
	MaxAllowedBudget         int64 // maximum allowed budget in base units (<= 0 for unlimited)
	OnBudgetExceeded         func(currentCost int64)
}

// SniffResult represents the accounting outcome of a stream.
type SniffResult struct {
	PromptTokens     int64
	CompletionTokens int64
	TotalCost        int64
	TerminatedEarly  bool
	ErrorMessage     string
}

// StreamSniffer intercepts SSE data streams to perform real-time Token metering and circuit-breaking.
type StreamSniffer struct {
	opts SniffOptions
}

// NewStreamSniffer creates a new StreamSniffer instance.
func NewStreamSniffer(opts SniffOptions) *StreamSniffer {
	return &StreamSniffer{opts: opts}
}

type sseUsagePayload struct {
	Usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		TotalTokens      int64 `json:"total_tokens"`
	} `json:"usage"`
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
}

// SniffAndForward streams lines from upstream, counts tokens, forwards chunks downstream,
// and breaks the stream immediately if the accrued cost breaches MaxAllowedBudget.
func (s *StreamSniffer) SniffAndForward(w http.ResponseWriter, upstream io.Reader) (*SniffResult, error) {
	scanner := bufio.NewScanner(upstream)
	// Allow large buffers up to 1MB per SSE event line
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	flusher, hasFlusher := w.(http.Flusher)

	res := &SniffResult{
		PromptTokens: s.opts.EstimatedPromptTokens,
	}

	var estimatedCompletionTokens int64

	promptCost := (res.PromptTokens * s.opts.PromptPriceBaseUnits) / 1000

	for scanner.Scan() {
		line := scanner.Text()

		// SSE line processing
		if strings.HasPrefix(line, "data: ") {
			dataPayload := strings.TrimSpace(strings.TrimPrefix(line, "data: "))

			if dataPayload != "[DONE]" && len(dataPayload) > 0 {
				var payload sseUsagePayload
				if err := json.Unmarshal([]byte(dataPayload), &payload); err == nil {
					// 1. Check if upstream explicitly reported usage
					if payload.Usage != nil {
						if payload.Usage.PromptTokens > 0 {
							res.PromptTokens = payload.Usage.PromptTokens
							promptCost = (res.PromptTokens * s.opts.PromptPriceBaseUnits) / 1000
						}
						if payload.Usage.CompletionTokens > 0 {
							res.CompletionTokens = payload.Usage.CompletionTokens
						}
					} else {
						// 2. Incrementally estimate tokens from content delta with rune-aware token estimation
						for _, choice := range payload.Choices {
							content := choice.Delta.Content
							if len(content) > 0 {
								estimatedCompletionTokens += EstimateTokensFromText(content)
							}
						}
					}
				}
			}
		}

		currentCompletion := res.CompletionTokens
		if currentCompletion == 0 {
			currentCompletion = estimatedCompletionTokens
		}
		currentCost := promptCost + (currentCompletion*s.opts.CompletionPriceBaseUnits)/1000

		// Check budget limit
		if s.opts.MaxAllowedBudget > 0 && currentCost > s.opts.MaxAllowedBudget {
			res.TerminatedEarly = true
			res.ErrorMessage = "Wallet balance exhausted during streaming generation."
			res.CompletionTokens = currentCompletion
			res.TotalCost = currentCost

			if s.opts.OnBudgetExceeded != nil {
				s.opts.OnBudgetExceeded(currentCost)
			}

			// Send explicit error chunk frame to downstream
			errFrame := "data: {\"error\": {\"code\": \"STREAM_BUDGET_EXHAUSTED\", \"message\": \"Wallet balance exhausted during streaming generation. Generation terminated by AgentFinOps financial firewall.\"}}\n\n"
			_, _ = w.Write([]byte(errFrame))
			if hasFlusher {
				flusher.Flush()
			}
			return res, ErrBudgetExhausted
		}

		// Write line to downstream
		_, err := fmt.Fprintf(w, "%s\n", line)
		if err != nil {
			// Client disconnected prematurely
			res.TerminatedEarly = true
			res.CompletionTokens = currentCompletion
			res.TotalCost = currentCost
			return res, err
		}

		// If line is empty, it signifies the end of an SSE event; flush to client immediately
		if line == "" && hasFlusher {
			flusher.Flush()
		}
	}

	if err := scanner.Err(); err != nil {
		res.ErrorMessage = err.Error()
	}

	if res.CompletionTokens == 0 {
		res.CompletionTokens = estimatedCompletionTokens
	}
	res.TotalCost = promptCost + (res.CompletionTokens*s.opts.CompletionPriceBaseUnits)/1000

	if hasFlusher {
		flusher.Flush()
	}

	return res, scanner.Err()
}

// EstimateTokensFromText estimates token count from text using Unicode rune categorization.
// CJK runes are typically ~0.8-1.5 tokens each, while Latin words/symbols average ~3.5-4 chars per token.
func EstimateTokensFromText(text string) int64 {
	var cjkCount int64
	var otherCount int64
	for _, r := range text {
		if (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF) || (r >= 0xF900 && r <= 0xFAFF) {
			cjkCount++
		} else {
			otherCount++
		}
	}
	tokens := cjkCount + (otherCount+3)/4
	if tokens < 1 && len(text) > 0 {
		tokens = 1
	}
	return tokens
}
