package agent

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Standard Policy Decision Error Codes conforming to protocol taxonomy
const (
	CodeAllow                 = "ALLOW"
	CodeAgentSuspended        = "ERR_AGENT_SUSPENDED"
	CodeAgentRevoked          = "ERR_AGENT_REVOKED"
	CodePolicyMaxPerTx        = "ERR_POLICY_MAX_PER_TX"
	CodePolicyBudgetExceeded  = "ERR_POLICY_BUDGET_EXCEEDED"
	CodeRateLimitExceeded     = "ERR_RATE_LIMIT_EXCEEDED"
	CodeRouteNotAllowed       = "ERR_ROUTE_NOT_ALLOWED"
)

type rateWindow struct {
	windowStart time.Time
	count       int
}

type budgetEntry struct {
	timestamp time.Time
	amount    int64
}

// Enforcer performs synchronous, in-path policy evaluations for Agents.
type Enforcer struct {
	mu           sync.Mutex
	rateWindows  map[string]*rateWindow    // agent_id -> rateWindow
	spendHistory map[string][]budgetEntry  // agent_id -> 24h history
}

// NewEnforcer creates an initialized synchronous policy enforcer.
func NewEnforcer() *Enforcer {
	return &Enforcer{
		rateWindows:  make(map[string]*rateWindow),
		spendHistory: make(map[string][]budgetEntry),
	}
}

// Evaluate synchronously checks all Agent-level policies against the current request.
func (e *Enforcer) Evaluate(
	ctx context.Context,
	agent *AgentIdentity,
	policy *AgentPolicyConfig,
	routeID string,
	routePath string,
	amountBaseUnits int64,
) PolicyDecision {
	// 1. Kill Switch Check (Instant Enforcement)
	if agent.Status == AgentStatusSuspended {
		return PolicyDecision{
			Allowed:    false,
			ReasonCode: CodeAgentSuspended,
			Reason:     fmt.Sprintf("Agent %s is currently suspended by administrator kill-switch", agent.AgentID),
			RuleID:     "rule_kill_switch_suspended",
		}
	}
	if agent.Status == AgentStatusRevoked {
		return PolicyDecision{
			Allowed:    false,
			ReasonCode: CodeAgentRevoked,
			Reason:     fmt.Sprintf("Agent %s has been permanently revoked", agent.AgentID),
			RuleID:     "rule_kill_switch_revoked",
		}
	}

	// If no custom policy defined, default to ALLOW
	if policy == nil {
		return PolicyDecision{Allowed: true, ReasonCode: CodeAllow, Reason: "Default allow (no custom agent policy)"}
	}

	// 2. Route Allowlist Check
	if len(policy.RouteAllowlist) > 0 {
		matched := false
		for _, allowed := range policy.RouteAllowlist {
			if allowed == routeID || allowed == routePath {
				matched = true
				break
			}
		}
		if !matched {
			return PolicyDecision{
				Allowed:    false,
				ReasonCode: CodeRouteNotAllowed,
				Reason:     fmt.Sprintf("Route %s is not in Agent %s allowlist", routeID, agent.AgentID),
				RuleID:     "rule_route_allowlist",
			}
		}
	}

	// 3. Max Amount Per Request (Single Transaction Ceiling)
	if policy.MaxAmountPerRequest > 0 && amountBaseUnits > policy.MaxAmountPerRequest {
		return PolicyDecision{
			Allowed:    false,
			ReasonCode: CodePolicyMaxPerTx,
			Reason: fmt.Sprintf("Request amount %d exceeds Agent max per-transaction limit %d",
				amountBaseUnits, policy.MaxAmountPerRequest),
			RuleID: "rule_max_amount_per_tx",
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()

	// 4. Rate Limiting (RPM sliding window)
	if policy.RateLimitRPM > 0 {
		w, ok := e.rateWindows[agent.AgentID]
		if !ok || now.Sub(w.windowStart) >= time.Minute {
			w = &rateWindow{windowStart: now, count: 0}
			e.rateWindows[agent.AgentID] = w
		}
		if w.count >= policy.RateLimitRPM {
			return PolicyDecision{
				Allowed:    false,
				ReasonCode: CodeRateLimitExceeded,
				Reason: fmt.Sprintf("Agent %s rate limit exceeded (%d/%d RPM)",
					agent.AgentID, w.count, policy.RateLimitRPM),
				RuleID: "rule_rate_limit_rpm",
			}
		}
		w.count++
	}

	// 5. Rolling 24h Budget Cap
	if policy.Rolling24hBudgetCap > 0 {
		cutoff := now.Add(-24 * time.Hour)
		history := e.spendHistory[agent.AgentID]

		// Prune entries older than 24 hours
		validIdx := 0
		var rollingTotal int64
		for _, item := range history {
			if item.timestamp.After(cutoff) {
				history[validIdx] = item
				validIdx++
				rollingTotal += item.amount
			}
		}
		history = history[:validIdx]
		e.spendHistory[agent.AgentID] = history

		if rollingTotal+amountBaseUnits > policy.Rolling24hBudgetCap {
			return PolicyDecision{
				Allowed:    false,
				ReasonCode: CodePolicyBudgetExceeded,
				Reason: fmt.Sprintf("Agent %s rolling 24h budget exceeded (current: %d, requested: %d, cap: %d)",
					agent.AgentID, rollingTotal, amountBaseUnits, policy.Rolling24hBudgetCap),
				RuleID: "rule_rolling_24h_budget",
			}
		}
	}

	return PolicyDecision{
		Allowed:    true,
		ReasonCode: CodeAllow,
		Reason:     "All Agent policy checks passed",
	}
}

// RecordSpend records financial expenditure for an Agent into the rolling 24h budget tracker.
func (e *Enforcer) RecordSpend(agentID string, amountBaseUnits int64) {
	if amountBaseUnits <= 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	e.spendHistory[agentID] = append(e.spendHistory[agentID], budgetEntry{
		timestamp: time.Now(),
		amount:    amountBaseUnits,
	})
}
