package payment

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Service defines operations for managing PaymentIntent, SettlementRecord, FulfillmentRecord,
// and assembling composite payment audit records (T5.2).
type Service interface {
	CreateWalletChallenge(ctx context.Context, challenge *WalletChallenge) error
	ConsumeWalletChallenge(ctx context.Context, challengeID, tenantID, walletID, apiKeyHash, routeID, requestBinding, nonce, idempotencyKey string, amount int64, now time.Time) (*WalletChallenge, error)
	SetWalletChallengeHold(ctx context.Context, challengeID, holdID string) error
	RejectWalletChallenge(ctx context.Context, challengeID string) error
	CreateIntent(ctx context.Context, intent *PaymentIntent) error
	GetIntent(ctx context.Context, intentID string) (*PaymentIntent, error)
	UpdateIntentStatus(ctx context.Context, intentID string, status string) error

	RecordSettlement(ctx context.Context, settlement *SettlementRecord) error
	GetSettlement(ctx context.Context, settlementID string) (*SettlementRecord, error)
	GetSettlementByIntent(ctx context.Context, intentID string) (*SettlementRecord, error)
	UpdateSettlementStatus(ctx context.Context, settlementID string, status string, txHash string, blockNumber *int64, errMsg string) error
	ListNonTerminalSettlements(ctx context.Context) ([]*SettlementRecord, error)

	RecordFulfillment(ctx context.Context, fulfillment *FulfillmentRecord) error
	GetFulfillment(ctx context.Context, fulfillmentID string) (*FulfillmentRecord, error)
	GetFulfillmentByIntent(ctx context.Context, intentID string) (*FulfillmentRecord, error)
	UpdateFulfillment(ctx context.Context, fulfillmentID string, status string, upstreamStatus int, latencyMs int64, bodyHash string) error

	// LinkWalletAssociation associates wallet hold and ledger entry with an intent
	LinkWalletAssociation(ctx context.Context, intentID string, hold *WalletHoldAssociation, ledger *LedgerAssociation) error
	ExpireStaleHolds(ctx context.Context, before time.Time) (int64, error)

	// Composite Query APIs
	GetPaymentAudit(ctx context.Context, tenantID, intentID string) (*PaymentAuditRecord, error)
	GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string) (*PaymentAuditRecord, error)
	ListPaymentAudits(ctx context.Context, filter PaymentAuditFilter) ([]*PaymentAuditRecord, int64, error)
}

// MemoryService provides a high-performance in-memory implementation of Service.
type MemoryService struct {
	mu                  sync.RWMutex
	intents             map[string]*PaymentIntent
	intentsByReq        map[string]string // request_id -> intent_id
	settlements         map[string]*SettlementRecord
	settlementByIntent  map[string]string // intent_id -> settlement_id
	fulfillments        map[string]*FulfillmentRecord
	fulfillmentByIntent map[string]string // intent_id -> fulfillment_id
	holdsByIntent       map[string]*WalletHoldAssociation
	ledgersByIntent     map[string]*LedgerAssociation
	walletChallenges    map[string]*WalletChallenge
	walletNonces        map[string]bool
}

// NewMemoryService creates a thread-safe in-memory payment correlation service.
func NewMemoryService() *MemoryService {
	return &MemoryService{
		intents:             make(map[string]*PaymentIntent),
		intentsByReq:        make(map[string]string),
		settlements:         make(map[string]*SettlementRecord),
		settlementByIntent:  make(map[string]string),
		fulfillments:        make(map[string]*FulfillmentRecord),
		fulfillmentByIntent: make(map[string]string),
		holdsByIntent:       make(map[string]*WalletHoldAssociation),
		ledgersByIntent:     make(map[string]*LedgerAssociation),
		walletChallenges:    make(map[string]*WalletChallenge),
		walletNonces:        make(map[string]bool),
	}
}

// CreateWalletChallenge saves the server-priced wallet quote before returning it to a buyer.
func (m *MemoryService) CreateWalletChallenge(ctx context.Context, ch *WalletChallenge) error {
	if ch == nil || ch.ChallengeID == "" || ch.IntentID == "" || ch.Amount <= 0 {
		return errors.New("invalid wallet challenge")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.walletChallenges[ch.ChallengeID]; exists {
		return errors.New("wallet challenge already exists")
	}
	cp := *ch
	cp.Status = "issued"
	m.walletChallenges[ch.ChallengeID] = &cp
	return nil
}

// ConsumeWalletChallenge atomically checks all challenge bindings and claims its one-time nonce.
// SECURITY-REVIEW: callers must do this before creating a wallet hold; failed claims must fail closed.
func (m *MemoryService) ConsumeWalletChallenge(ctx context.Context, challengeID, tenantID, walletID, apiKeyHash, routeID, requestBinding, nonce, idempotencyKey string, amount int64, now time.Time) (*WalletChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.walletChallenges[challengeID]
	if !ok || ch.Status != "issued" || now.Before(ch.ValidAfter) || now.After(ch.ValidBefore) ||
		ch.TenantID != tenantID || ch.WalletID != walletID || ch.APIKeyHash != apiKeyHash || ch.RouteID != routeID ||
		ch.RequestBinding != requestBinding || ch.IdempotencyKey != idempotencyKey || ch.Amount != amount || nonce == "" {
		return nil, ErrWalletChallengeInvalid
	}
	if m.walletNonces[walletID+":"+nonce] {
		return nil, ErrWalletChallengeReplay
	}
	m.walletNonces[walletID+":"+nonce] = true
	ch.Status = "consuming"
	cp := *ch
	return &cp, nil
}

func (m *MemoryService) SetWalletChallengeHold(ctx context.Context, challengeID, holdID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.walletChallenges[challengeID]
	if !ok || ch.Status != "consuming" || holdID == "" {
		return ErrWalletChallengeInvalid
	}
	ch.HoldID = holdID
	ch.Status = "consumed"
	return nil
}

func (m *MemoryService) RejectWalletChallenge(ctx context.Context, challengeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.walletChallenges[challengeID]
	if !ok || ch.Status != "consuming" {
		return ErrWalletChallengeInvalid
	}
	ch.Status = "rejected"
	return nil
}

func (m *MemoryService) CreateIntent(ctx context.Context, intent *PaymentIntent) error {
	if intent == nil || intent.IntentID == "" {
		return errors.New("invalid payment intent")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if existing, exists := m.intents[intent.IntentID]; exists {
		cp := *existing
		cp.Status = intent.Status
		if intent.RequestID != "" {
			cp.RequestID = intent.RequestID
		}
		if intent.IdempotencyKey != "" {
			cp.IdempotencyKey = intent.IdempotencyKey
		}
		if intent.AgentID != "" {
			cp.AgentID = intent.AgentID
		}
		cp.UpdatedAt = now
		m.intents[cp.IntentID] = &cp
		if cp.RequestID != "" {
			m.intentsByReq[cp.RequestID] = cp.IntentID
		}
		return nil
	}
	if intent.CreatedAt.IsZero() {
		intent.CreatedAt = now
	}
	intent.UpdatedAt = now

	cp := *intent
	m.intents[cp.IntentID] = &cp
	if cp.RequestID != "" {
		m.intentsByReq[cp.RequestID] = cp.IntentID
	}
	return nil
}

func (m *MemoryService) GetIntent(ctx context.Context, intentID string) (*PaymentIntent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return nil, ErrIntentNotFound
	}
	cp := *intent
	return &cp, nil
}

func (m *MemoryService) UpdateIntentStatus(ctx context.Context, intentID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return ErrIntentNotFound
	}
	intent.Status = status
	intent.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryService) RecordSettlement(ctx context.Context, settlement *SettlementRecord) error {
	if settlement == nil || settlement.SettlementID == "" || settlement.IntentID == "" {
		return errors.New("invalid settlement record")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if settlement.CreatedAt.IsZero() {
		settlement.CreatedAt = now
	}
	settlement.UpdatedAt = now

	cp := *settlement
	m.settlements[cp.SettlementID] = &cp
	m.settlementByIntent[cp.IntentID] = cp.SettlementID
	return nil
}

func (m *MemoryService) GetSettlement(ctx context.Context, settlementID string) (*SettlementRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.settlements[settlementID]
	if !ok {
		return nil, ErrSettlementNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *MemoryService) GetSettlementByIntent(ctx context.Context, intentID string) (*SettlementRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sID, ok := m.settlementByIntent[intentID]
	if !ok {
		return nil, ErrSettlementNotFound
	}
	s, ok := m.settlements[sID]
	if !ok {
		return nil, ErrSettlementNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *MemoryService) UpdateSettlementStatus(ctx context.Context, settlementID string, status string, txHash string, blockNumber *int64, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.settlements[settlementID]
	if !ok {
		return ErrSettlementNotFound
	}
	s.Status = status
	if txHash != "" {
		s.TxHash = txHash
	}
	if blockNumber != nil {
		s.BlockNumber = blockNumber
	}
	if errMsg != "" {
		s.ErrorMessage = errMsg
	}
	s.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryService) ListNonTerminalSettlements(ctx context.Context) ([]*SettlementRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*SettlementRecord
	for _, s := range m.settlements {
		if s.Status == SettlementStatusSubmitted || s.Status == SettlementStatusPending || s.Status == SettlementStatusUnknown {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemoryService) RecordFulfillment(ctx context.Context, fulfillment *FulfillmentRecord) error {
	if fulfillment == nil || fulfillment.FulfillmentID == "" || fulfillment.IntentID == "" {
		return errors.New("invalid fulfillment record")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if fulfillment.CreatedAt.IsZero() {
		fulfillment.CreatedAt = now
	}
	fulfillment.UpdatedAt = now

	cp := *fulfillment
	m.fulfillments[cp.FulfillmentID] = &cp
	m.fulfillmentByIntent[cp.IntentID] = cp.FulfillmentID
	return nil
}

func (m *MemoryService) GetFulfillment(ctx context.Context, fulfillmentID string) (*FulfillmentRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, ok := m.fulfillments[fulfillmentID]
	if !ok {
		return nil, ErrFulfillmentNotFound
	}
	cp := *f
	return &cp, nil
}

func (m *MemoryService) GetFulfillmentByIntent(ctx context.Context, intentID string) (*FulfillmentRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fID, ok := m.fulfillmentByIntent[intentID]
	if !ok {
		return nil, ErrFulfillmentNotFound
	}
	f, ok := m.fulfillments[fID]
	if !ok {
		return nil, ErrFulfillmentNotFound
	}
	cp := *f
	return &cp, nil
}

func (m *MemoryService) UpdateFulfillment(ctx context.Context, fulfillmentID string, status string, upstreamStatus int, latencyMs int64, bodyHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, ok := m.fulfillments[fulfillmentID]
	if !ok {
		return ErrFulfillmentNotFound
	}
	f.Status = status
	if upstreamStatus > 0 {
		f.UpstreamStatus = upstreamStatus
	}
	if latencyMs > 0 {
		f.LatencyMs = latencyMs
	}
	if bodyHash != "" {
		f.ResponseBodyHash = bodyHash
	}
	f.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryService) LinkWalletAssociation(ctx context.Context, intentID string, hold *WalletHoldAssociation, ledger *LedgerAssociation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hold != nil {
		hCopy := *hold
		m.holdsByIntent[intentID] = &hCopy
	}
	if ledger != nil {
		lCopy := *ledger
		m.ledgersByIntent[intentID] = &lCopy
	}
	return nil
}

func (m *MemoryService) ExpireStaleHolds(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var count int64
	for intentID, h := range m.holdsByIntent {
		if h.Status == "held" && !h.ExpiresAt.IsZero() && h.ExpiresAt.Before(before) {
			h.Status = "expired"
			if sID, ok := m.settlementByIntent[intentID]; ok {
				if s, exists := m.settlements[sID]; exists && s.Status == SettlementStatusHeld {
					s.Status = SettlementStatusReleased
					s.UpdatedAt = before
				}
			}
			if intent, exists := m.intents[intentID]; exists && intent.Status == IntentStatusAuthorized {
				intent.Status = IntentStatusExpired
				intent.UpdatedAt = before
			}
			count++
		}
	}
	return count, nil
}

func (m *MemoryService) buildAuditRecordLocked(intent *PaymentIntent) *PaymentAuditRecord {
	settlementStatus := SettlementStatusNotStarted
	var settlementCopy *SettlementRecord
	if sID, ok := m.settlementByIntent[intent.IntentID]; ok {
		if s, exists := m.settlements[sID]; exists {
			cp := *s
			settlementCopy = &cp
			settlementStatus = s.Status
		}
	}

	fulfillmentStatus := FulfillmentStatusNotStarted
	var fulfillmentCopy *FulfillmentRecord
	if fID, ok := m.fulfillmentByIntent[intent.IntentID]; ok {
		if f, exists := m.fulfillments[fID]; exists {
			cp := *f
			fulfillmentCopy = &cp
			fulfillmentStatus = f.Status
		}
	}

	var holdCopy *WalletHoldAssociation
	if h, exists := m.holdsByIntent[intent.IntentID]; exists {
		cp := *h
		holdCopy = &cp
	}

	var ledgerCopy *LedgerAssociation
	if l, exists := m.ledgersByIntent[intent.IntentID]; exists {
		cp := *l
		ledgerCopy = &cp
	}

	displayStatus, displayNote, isRecovery := DeriveCompositeDisplayStatus(intent.Status, settlementStatus, fulfillmentStatus)

	intentCopy := *intent
	return &PaymentAuditRecord{
		IntentID:           intent.IntentID,
		TenantID:           intent.TenantID,
		ProjectID:          intent.ProjectID,
		AgentID:            intent.AgentID,
		RouteID:            intent.RouteID,
		RequestID:          intent.RequestID,
		IdempotencyKey:     intent.IdempotencyKey,
		PaymentMethod:      intent.PaymentMethod,
		AmountBaseUnits:    intent.AmountBaseUnits,
		Asset:              intent.Asset,
		DisplayStatus:      displayStatus,
		DisplayNote:        displayNote,
		IsRecoveryRequired: isRecovery,
		IntentStatus:       intent.Status,
		SettlementStatus:   settlementStatus,
		FulfillmentStatus:  fulfillmentStatus,
		Intent:             &intentCopy,
		Settlement:         settlementCopy,
		Fulfillment:        fulfillmentCopy,
		Hold:               holdCopy,
		Ledger:             ledgerCopy,
		CreatedAt:          intent.CreatedAt,
		UpdatedAt:          intent.UpdatedAt,
	}
}

func (m *MemoryService) GetPaymentAudit(ctx context.Context, tenantID, intentID string) (*PaymentAuditRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return nil, ErrIntentNotFound
	}
	if tenantID != "" && intent.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return m.buildAuditRecordLocked(intent), nil
}

func (m *MemoryService) GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string) (*PaymentAuditRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	intentID, ok := m.intentsByReq[requestID]
	if !ok {
		return nil, ErrIntentNotFound
	}
	intent, ok := m.intents[intentID]
	if !ok {
		return nil, ErrIntentNotFound
	}
	if tenantID != "" && intent.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return m.buildAuditRecordLocked(intent), nil
}

func (m *MemoryService) ListPaymentAudits(ctx context.Context, filter PaymentAuditFilter) ([]*PaymentAuditRecord, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matched []*PaymentAuditRecord
	for _, intent := range m.intents {
		if filter.TenantID != "" && intent.TenantID != filter.TenantID {
			continue
		}
		if filter.ProjectID != "" && intent.ProjectID != filter.ProjectID {
			continue
		}
		if filter.AgentID != "" && intent.AgentID != filter.AgentID {
			continue
		}
		if filter.RouteID != "" && intent.RouteID != filter.RouteID {
			continue
		}
		if filter.PaymentMethod != "" && intent.PaymentMethod != filter.PaymentMethod {
			continue
		}
		if filter.IntentStatus != "" && intent.Status != filter.IntentStatus {
			continue
		}
		if filter.StartTime != nil && intent.CreatedAt.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && intent.CreatedAt.After(*filter.EndTime) {
			continue
		}

		auditRec := m.buildAuditRecordLocked(intent)
		if filter.DisplayStatus != "" && auditRec.DisplayStatus != filter.DisplayStatus {
			continue
		}
		matched = append(matched, auditRec)
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	if filter.Offset >= len(matched) {
		return []*PaymentAuditRecord{}, total, nil
	}

	end := len(matched)
	if filter.Limit > 0 && filter.Offset+filter.Limit < end {
		end = filter.Offset + filter.Limit
	}

	res := make([]*PaymentAuditRecord, end-filter.Offset)
	copy(res, matched[filter.Offset:end])
	return res, total, nil
}
