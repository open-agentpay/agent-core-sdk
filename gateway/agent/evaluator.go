package agent

import "context"

// PolicyRequest encapsulates the in-flight request context evaluated by a PolicyEvaluator.
type PolicyRequest struct {
	Agent       *AgentIdentity         `json:"agent"`
	Policy      *AgentPolicyConfig     `json:"policy,omitempty"`
	RouteID     string                 `json:"route_id"`
	RoutePath   string                 `json:"route_path"`
	AmountBase  int64                  `json:"amount_base_units"`
	Currency    string                 `json:"currency"`
	Declared    *DeclaredContext       `json:"declared,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEvaluator defines the synchronous in-path policy evaluation interface.
type PolicyEvaluator interface {
	EvaluatePolicy(ctx context.Context, req *PolicyRequest) PolicyDecision
}

// SpendRecord contains execution details of a captured payment transaction.
type SpendRecord struct {
	TenantID   string                 `json:"tenant_id"`
	ProjectID  string                 `json:"project_id"`
	AgentID    string                 `json:"agent_id"`
	RouteID    string                 `json:"route_id"`
	AmountBase int64                  `json:"amount_base_units"`
	Currency   string                 `json:"currency"`
	HoldID     string                 `json:"hold_id"`
	CapturedAt int64                  `json:"captured_at"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SpendRecorder defines a listener for post-capture financial expenditure events.
type SpendRecorder interface {
	RecordSpend(ctx context.Context, record *SpendRecord) error
}

// EvaluatorFunc is an adapter to allow the use of ordinary functions as PolicyEvaluators.
type EvaluatorFunc func(ctx context.Context, req *PolicyRequest) PolicyDecision

// EvaluatePolicy calls f(ctx, req).
func (f EvaluatorFunc) EvaluatePolicy(ctx context.Context, req *PolicyRequest) PolicyDecision {
	return f(ctx, req)
}

// ChainEvaluator chains multiple evaluators in order; halts on first rejection.
type ChainEvaluator []PolicyEvaluator

// EvaluatePolicy executes each evaluator in sequence until one rejects or all pass.
func (c ChainEvaluator) EvaluatePolicy(ctx context.Context, req *PolicyRequest) PolicyDecision {
	for _, e := range c {
		if e == nil {
			continue
		}
		decision := e.EvaluatePolicy(ctx, req)
		if !decision.Allowed {
			return decision
		}
	}
	return PolicyDecision{Allowed: true, ReasonCode: CodeAllow, Reason: "All policy evaluators passed"}
}
