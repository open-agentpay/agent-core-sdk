package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

var (
	ErrAPIKeyNotFound = errors.New("API key not found or inactive")
	ErrAgentNotFound  = errors.New("agent not found")
)

// Registry manages in-memory caching of Agent identities, API Key bindings,
// and real-time lifecycle states for millisecond-latency resolution and Kill Switch enforcement.
type Registry struct {
	mu           sync.RWMutex
	agents       map[string]*AgentIdentity      // agent_id -> identity
	keyToAgent   map[string]string              // key_hash -> agent_id
	policies     map[string]*AgentPolicyConfig  // agent_id -> policy
}

// NewRegistry creates a thread-safe Agent Registry.
func NewRegistry() *Registry {
	return &Registry{
		agents:     make(map[string]*AgentIdentity),
		keyToAgent: make(map[string]string),
		policies:   make(map[string]*AgentPolicyConfig),
	}
}

// RegisterAgent registers or updates an Agent identity and optional policy config.
func (r *Registry) RegisterAgent(agent *AgentIdentity, policy *AgentPolicyConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.agents[agent.AgentID] = agent
	if policy != nil {
		r.policies[agent.AgentID] = policy
	}
}

// BindAPIKey maps a plaintext API key to an Agent via SHA-256 hash.
func (r *Registry) BindAPIKey(apiKey string, agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])
	r.keyToAgent[keyHash] = agentID
}

// BindAPIKeyHash directly maps a precomputed SHA-256 hash to an Agent.
func (r *Registry) BindAPIKeyHash(keyHash string, agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.keyToAgent[keyHash] = agentID
}

// RevokeKey removes the key mapping from the in-memory cache.
func (r *Registry) RevokeKey(keyHash string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.keyToAgent, keyHash)
}

// UnbindAPIKeyHash removes the key mapping from the registry.
func (r *Registry) UnbindAPIKeyHash(keyHash string) {
	r.RevokeKey(keyHash)
}

// SetAgentStatus updates the Agent lifecycle status instantly (Kill Switch channel).
// When status is set to AgentStatusSuspended or AgentStatusRevoked, any subsequent
// request using this Agent's keys is immediately rejected in the fast-path.
func (r *Registry) SetAgentStatus(agentID string, status AgentStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	agent, ok := r.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	agent.Status = status
	return nil
}

// ResolveAPIKey resolves the observed AgentIdentity and policy config given a plaintext API key.
func (r *Registry) ResolveAPIKey(apiKey string) (*AgentIdentity, *AgentPolicyConfig, error) {
	hash := sha256.Sum256([]byte(apiKey))
	keyHash := hex.EncodeToString(hash[:])

	r.mu.RLock()
	defer r.mu.RUnlock()

	agentID, ok := r.keyToAgent[keyHash]
	if !ok {
		return nil, nil, ErrAPIKeyNotFound
	}

	agent, ok := r.agents[agentID]
	if !ok {
		return nil, nil, ErrAgentNotFound
	}

	policy := r.policies[agentID]
	return agent, policy, nil
}

// GetAgent returns the current AgentIdentity by Agent ID.
func (r *Registry) GetAgent(agentID string) (*AgentIdentity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agent, ok := r.agents[agentID]
	if !ok {
		return nil, false
	}
	// Return shallow copy
	copy := *agent
	return &copy, true
}

// SetPolicy sets or updates the policy configuration for an Agent.
func (r *Registry) SetPolicy(policy *AgentPolicyConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.policies[policy.AgentID] = policy
}
