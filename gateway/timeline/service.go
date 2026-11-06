package timeline

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/agent-core-sdk/gateway/agent"
)

// Service defines the interface for Agent timeline reading and indexing (T5.8).
type Service interface {
	RecordEvent(ctx context.Context, event *agent.AuditEvent) error
	GetTimeline(ctx context.Context, tenantID, agentID string, filter TimelineFilter) ([]*TimelineEvent, int64, []string, error)
}

// MemoryService provides a high-performance in-memory timeline read model.
type MemoryService struct {
	mu     sync.RWMutex
	events []*agent.AuditEvent
}

// NewMemoryService creates a new in-memory timeline service.
func NewMemoryService() *MemoryService {
	return &MemoryService{
		events: make([]*agent.AuditEvent, 0),
	}
}

// RecordEvent appends an audit event to the memory store.
func (m *MemoryService) RecordEvent(ctx context.Context, event *agent.AuditEvent) error {
	if event == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Shallow clone
	cp := *event
	m.events = append(m.events, &cp)
	return nil
}

// GetTimeline retrieves a paginated and filtered timeline of events for an Agent.
func (m *MemoryService) GetTimeline(ctx context.Context, tenantID, agentID string, filter TimelineFilter) ([]*TimelineEvent, int64, []string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*agent.AuditEvent
	sessionsMap := make(map[string]struct{})

	for _, e := range m.events {
		// Strict multi-tenant isolation (T1.8 §1 & T5.8)
		if tenantID != "" && e.TenantID != tenantID {
			continue
		}
		if agentID != "" && e.AgentID != agentID {
			continue
		}
		if filter.ProjectID != "" && e.ProjectID != filter.ProjectID {
			continue
		}

		// Collect distinct declared sessions for this agent
		if e.Declared != nil && e.Declared.SessionID != "" {
			sessionsMap[e.Declared.SessionID] = struct{}{}
		}

		// Filter by declared session_id
		if filter.SessionID != "" && filter.SessionID != "all" {
			if e.Declared == nil || e.Declared.SessionID != filter.SessionID {
				continue
			}
		}

		// Filter by declared task_id
		if filter.TaskID != "" && filter.TaskID != "all" {
			if e.Declared == nil || e.Declared.TaskID != filter.TaskID {
				continue
			}
		}

		// Filter by event_type
		if filter.EventType != "" && filter.EventType != "all" {
			if e.EventType != filter.EventType {
				continue
			}
		}

		// Filter by time range
		if filter.StartTime != nil || filter.EndTime != nil {
			t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil {
				t, err = time.Parse(time.RFC3339, e.Timestamp)
			}
			if err == nil {
				if filter.StartTime != nil && t.Before(*filter.StartTime) {
					continue
				}
				if filter.EndTime != nil && t.After(*filter.EndTime) {
					continue
				}
			}
		}

		matched = append(matched, e)
	}

	// Sort reverse-chronologically (newest first)
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Timestamp > matched[j].Timestamp
	})

	total := int64(len(matched))

	// Pagination
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(matched) {
		return []*TimelineEvent{}, total, extractDistinctSessions(sessionsMap), nil
	}

	end := len(matched)
	if filter.Limit > 0 && offset+filter.Limit < end {
		end = offset + filter.Limit
	}

	res := make([]*TimelineEvent, 0, end-offset)
	for _, e := range matched[offset:end] {
		res = append(res, FromAuditEvent(e))
	}

	return res, total, extractDistinctSessions(sessionsMap), nil
}

func extractDistinctSessions(m map[string]struct{}) []string {
	sessions := make([]string, 0, len(m))
	for s := range m {
		sessions = append(sessions, s)
	}
	sort.Strings(sessions)
	return sessions
}
