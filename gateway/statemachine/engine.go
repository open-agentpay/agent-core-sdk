package statemachine

import (
	"encoding/json"
	"fmt"
	"os"
)

// StateSpec defines state attributes.
type StateSpec struct {
	Description string `json:"description"`
	IsTerminal  bool   `json:"is_terminal"`
}

// TransitionSpec defines a legal state transition.
type TransitionSpec struct {
	From        string `json:"from"`
	Event       string `json:"event"`
	To          string `json:"to"`
	Description string `json:"description"`
}

// EntitySpec defines entity state machine schema.
type EntitySpec struct {
	InitialState string                    `json:"initial_state"`
	States       map[string]StateSpec      `json:"states"`
	Transitions  []TransitionSpec          `json:"transitions"`
}

// CompositeViewSpec defines mapping to user-facing composite view.
type CompositeViewSpec struct {
	Settlement  []string `json:"settlement"`
	Fulfillment []string `json:"fulfillment"`
	Display     string   `json:"display"`
	Description string   `json:"description"`
}

// InvariantSpec describes safety invariants.
type InvariantSpec struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	AppliesTo   string `json:"applies_to"`
}

// CoordinationSpec holds multi-entity invariants and composite views.
type CoordinationSpec struct {
	Invariants     []InvariantSpec     `json:"invariants"`
	CompositeViews []CompositeViewSpec `json:"composite_views"`
}

// Specification is the canonical representation of state-machine.json.
type Specification struct {
	Version                string                `json:"version"`
	Name                   string                `json:"name"`
	Description            string                `json:"description"`
	SupportedPaymentMethods []string             `json:"supported_payment_methods"`
	Entities               map[string]EntitySpec `json:"entities"`
	Coordination           CoordinationSpec      `json:"coordination"`
}

// Engine drives deterministic state machine transitions according to Specification.
type Engine struct {
	spec Specification
}

// LoadSpecificationFromFile parses state-machine.json from disk.
func LoadSpecificationFromFile(path string) (*Specification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state machine spec at %s: %w", path, err)
	}
	var spec Specification
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state machine spec: %w", err)
	}
	return &spec, nil
}

// NewEngine creates an engine instance.
func NewEngine(spec Specification) *Engine {
	return &Engine{spec: spec}
}

// Transition evaluates a state transition for an entity.
func (e *Engine) Transition(entityName string, currentState string, event string) (string, error) {
	entity, ok := e.spec.Entities[entityName]
	if !ok {
		return "", fmt.Errorf("unknown entity '%s'", entityName)
	}

	stateSpec, ok := entity.States[currentState]
	if !ok {
		return "", fmt.Errorf("unknown state '%s' for entity '%s'", currentState, entityName)
	}

	if stateSpec.IsTerminal {
		return "", fmt.Errorf("IllegalStateTransition: entity '%s' in terminal state '%s' cannot process event '%s'", entityName, currentState, event)
	}

	for _, t := range entity.Transitions {
		if t.From == currentState && t.Event == event {
			return t.To, nil
		}
	}

	return "", fmt.Errorf("IllegalStateTransition: no legal transition for entity '%s' from '%s' with event '%s'", entityName, currentState, event)
}

// CanDispatchFulfillment checks INV_1_DISPATCH_GUARD.
// - onchain_sync: requires settlement == "confirmed"
// - onchain_async: requires signature verified & nonce persisted (settlement == "submitted" or "confirmed")
// - wallet: requires settlement == "held"
func (e *Engine) CanDispatchFulfillment(settlementState string, paymentMethod string) bool {
	switch paymentMethod {
	case "wallet":
		return settlementState == "held"
	case "onchain_async":
		return settlementState == "submitted" || settlementState == "confirmed"
	case "onchain_sync", "onchain":
		return settlementState == "confirmed"
	default:
		return settlementState == "confirmed"
	}
}

// CanSubmitSettlement checks INV_2_UNKNOWN_SUBMIT_GUARD.
func (e *Engine) CanSubmitSettlement(settlementState string) bool {
	return settlementState == "not_started"
}

// DeriveCompositeView derives user-facing display status.
func (e *Engine) DeriveCompositeView(settlementState string, fulfillmentState string) string {
	for _, view := range e.spec.Coordination.CompositeViews {
		settlementMatched := false
		for _, s := range view.Settlement {
			if s == settlementState {
				settlementMatched = true
				break
			}
		}
		if !settlementMatched {
			continue
		}

		fulfillmentMatched := false
		for _, f := range view.Fulfillment {
			if f == fulfillmentState {
				fulfillmentMatched = true
				break
			}
		}
		if fulfillmentMatched {
			return view.Display
		}
	}
	return "UNKNOWN_COMPOSITE"
}

// IsTerminal returns if the given state is terminal.
func (e *Engine) IsTerminal(entityName string, state string) bool {
	entity, ok := e.spec.Entities[entityName]
	if !ok {
		return false
	}
	s, ok := entity.States[state]
	return ok && s.IsTerminal
}
