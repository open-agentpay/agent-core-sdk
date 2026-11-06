package usage

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrRequestRecordNotFound = errors.New("request record not found")
	ErrUsageEventNotFound    = errors.New("usage event not found")
	ErrTenantMismatch        = errors.New("resource does not belong to specified tenant")
)

// Service defines the contract for recording and querying inbound requests and usage events.
type Service interface {
	RecordRequest(ctx context.Context, record *RequestRecord) error
	RecordUsage(ctx context.Context, event *UsageEvent) error
	ListRequestRecords(ctx context.Context, filter RequestFilter) ([]*RequestRecord, int64, error)
	ListUsageEvents(ctx context.Context, filter UsageFilter) ([]*UsageEvent, int64, error)
	GetRequestRecord(ctx context.Context, tenantID, requestID string) (*RequestRecord, error)
	GetUsageEvent(ctx context.Context, tenantID, eventID string) (*UsageEvent, error)
}

// MemoryService provides an in-memory, thread-safe implementation of Service for testing & development.
type MemoryService struct {
	mu             sync.RWMutex
	requestRecords []*RequestRecord
	usageEvents    []*UsageEvent
	requestsByID   map[string]*RequestRecord
	usagesByID     map[string]*UsageEvent
}

// NewMemoryService creates an initialized in-memory Service.
func NewMemoryService() *MemoryService {
	return &MemoryService{
		requestRecords: make([]*RequestRecord, 0),
		usageEvents:    make([]*UsageEvent, 0),
		requestsByID:   make(map[string]*RequestRecord),
		usagesByID:     make(map[string]*UsageEvent),
	}
}

// RecordRequest records an inbound HTTP request event.
func (m *MemoryService) RecordRequest(ctx context.Context, record *RequestRecord) error {
	if record == nil {
		return errors.New("record cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if record.RequestID == "" {
		record.RequestID = GenerateRequestID()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}

	// Make a shallow copy to prevent external mutation
	copied := *record
	m.requestRecords = append(m.requestRecords, &copied)
	m.requestsByID[copied.RequestID] = &copied
	return nil
}

// RecordUsage records a metering usage event.
func (m *MemoryService) RecordUsage(ctx context.Context, event *UsageEvent) error {
	if event == nil {
		return errors.New("usage event cannot be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if event.EventID == "" {
		event.EventID = GenerateUsageEventID()
	}
	if event.Asset == "" {
		event.Asset = "USDC"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	copied := *event
	m.usageEvents = append(m.usageEvents, &copied)
	m.usagesByID[copied.EventID] = &copied
	return nil
}

// ListRequestRecords retrieves paginated request records matching the filter.
func (m *MemoryService) ListRequestRecords(ctx context.Context, filter RequestFilter) ([]*RequestRecord, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*RequestRecord
	for _, r := range m.requestRecords {
		if filter.TenantID != "" && r.TenantID != filter.TenantID {
			continue
		}
		if filter.ProjectID != "" && r.ProjectID != filter.ProjectID {
			continue
		}
		if filter.AgentID != "" && r.AgentID != filter.AgentID {
			continue
		}
		if filter.RouteID != "" && r.RouteID != filter.RouteID {
			continue
		}
		if filter.StatusCode != 0 && r.StatusCode != filter.StatusCode {
			continue
		}
		if filter.IsReplay != nil && r.IsReplay != *filter.IsReplay {
			continue
		}
		if filter.StartTime != nil && r.CreatedAt.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && r.CreatedAt.After(*filter.EndTime) {
			continue
		}
		matched = append(matched, r)
	}

	// Sort descending by created_at
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Offset >= len(matched) {
		return []*RequestRecord{}, total, nil
	}

	end := len(matched)
	if filter.Limit > 0 && filter.Offset+filter.Limit < end {
		end = filter.Offset + filter.Limit
	}

	res := make([]*RequestRecord, end-filter.Offset)
	copy(res, matched[filter.Offset:end])
	return res, total, nil
}

// ListUsageEvents retrieves paginated usage events matching the filter.
func (m *MemoryService) ListUsageEvents(ctx context.Context, filter UsageFilter) ([]*UsageEvent, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*UsageEvent
	for _, u := range m.usageEvents {
		if filter.TenantID != "" && u.TenantID != filter.TenantID {
			continue
		}
		if filter.ProjectID != "" && u.ProjectID != filter.ProjectID {
			continue
		}
		if filter.AgentID != "" && u.AgentID != filter.AgentID {
			continue
		}
		if filter.RouteID != "" && u.RouteID != filter.RouteID {
			continue
		}
		if filter.IntentID != "" && u.IntentID != filter.IntentID {
			continue
		}
		if filter.PaymentMethod != "" && u.PaymentMethod != filter.PaymentMethod {
			continue
		}
		if filter.IsSuccess != nil && u.IsSuccess != *filter.IsSuccess {
			continue
		}
		if filter.StartTime != nil && u.CreatedAt.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && u.CreatedAt.After(*filter.EndTime) {
			continue
		}
		matched = append(matched, u)
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Offset >= len(matched) {
		return []*UsageEvent{}, total, nil
	}

	end := len(matched)
	if filter.Limit > 0 && filter.Offset+filter.Limit < end {
		end = filter.Offset + filter.Limit
	}

	res := make([]*UsageEvent, end-filter.Offset)
	copy(res, matched[filter.Offset:end])
	return res, total, nil
}

// GetRequestRecord returns a specific request record by ID with tenant boundary validation.
func (m *MemoryService) GetRequestRecord(ctx context.Context, tenantID, requestID string) (*RequestRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.requestsByID[requestID]
	if !ok {
		return nil, ErrRequestRecordNotFound
	}
	if tenantID != "" && rec.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return rec, nil
}

// GetUsageEvent returns a specific usage event by ID with tenant boundary validation.
func (m *MemoryService) GetUsageEvent(ctx context.Context, tenantID, eventID string) (*UsageEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	evt, ok := m.usagesByID[eventID]
	if !ok {
		return nil, ErrUsageEventNotFound
	}
	if tenantID != "" && evt.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return evt, nil
}
