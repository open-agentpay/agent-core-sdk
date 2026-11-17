package admin

import (
	"context"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"strings"
	"time"
)

func (s *MemoryService) Register(ctx context.Context, tenantName, email, password string, currency ...string) (*Tenant, *Member, error) {
	cleanName := strings.TrimSpace(tenantName)
	cleanEmail := strings.TrimSpace(email)
	if cleanName == "" {
		return nil, nil, fmt.Errorf("tenant name cannot be empty")
	}
	if cleanEmail == "" {
		return nil, nil, fmt.Errorf("email cannot be empty")
	}
	if len(password) < 8 {
		return nil, nil, ErrPasswordTooShort
	}

	rawCurr := ""
	if len(currency) > 0 {
		rawCurr = strings.TrimSpace(currency[0])
	}
	curr, err := NormalizeCurrency(rawCurr)
	if err != nil {
		return nil, nil, err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tenants {
		if t.Name == cleanName {
			return nil, nil, ErrTenantAlreadyExists
		}
	}
	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			return nil, nil, ErrEmailAlreadyRegistered
		}
	}

	tid := GenerateTenantID()
	now := time.Now().Unix()
	t := &Tenant{
		TenantID:  tid,
		Name:      cleanName,
		Currency:  curr,
		Status:    TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.tenants[tid] = t

	ownerMember := &Member{
		MemberID:     GenerateMemberID(),
		TenantID:     tid,
		Email:        cleanEmail,
		PasswordHash: hash,
		Role:         RoleOwner,
		Status:       MemberStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.members[ownerMember.MemberID] = ownerMember
	s.initMasterWalletLocked(tid, curr)

	defaultPrjID := GenerateProjectID()
	s.projects[defaultPrjID] = &Project{
		ProjectID:          defaultPrjID,
		TenantID:           tid,
		Name:               "默认项目 (Default)",
		BudgetCapBaseUnits: 1000000000,
		Status:             ProjectStatusActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	s.recordAudit(tid, ownerMember.MemberID, "auth.register", "Tenant", tid, nil, map[string]interface{}{"email": cleanEmail, "tenant": cleanName, "currency": curr, "project_id": defaultPrjID}, "127.0.0.1")
	return t, ownerMember, nil
}

func (s *MemoryService) Login(ctx context.Context, email, password string) (*Member, *Tenant, error) {
	cleanEmail := strings.TrimSpace(email)
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matchedMember *Member
	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			matchedMember = m
			break
		}
	}
	if matchedMember == nil {
		return nil, nil, ErrInvalidCredentials
	}
	if matchedMember.Status != MemberStatusActive {
		return nil, nil, ErrMemberDisabled
	}

	tenant, ok := s.tenants[matchedMember.TenantID]
	if !ok || tenant.Status != TenantStatusActive {
		return nil, nil, ErrTenantSuspended
	}
	if matchedMember.PasswordHash == "" || !auth.VerifyPassword(password, matchedMember.PasswordHash) {
		return nil, nil, ErrInvalidCredentials
	}
	return matchedMember, tenant, nil
}

func (s *MemoryService) GetMemberByEmail(ctx context.Context, email string) (*Member, *Tenant, error) {
	cleanEmail := strings.TrimSpace(email)
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.members {
		if strings.EqualFold(m.Email, cleanEmail) {
			return m, s.tenants[m.TenantID], nil
		}
	}
	return nil, nil, ErrMemberNotFound
}

func (s *MemoryService) SetMemberPassword(ctx context.Context, tenantID, memberID, password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return ErrMemberNotFound
	}
	m.PasswordHash = hash
	m.UpdatedAt = time.Now().Unix()
	return nil
}

// ----------------------------------------------------------------------------
// Tenants
// ----------------------------------------------------------------------------

func (s *MemoryService) AddMember(ctx context.Context, tenantID, email string, role MemberRole, actorMemberID string) (*Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	if cleanEmail == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberCreate); err != nil {
		return nil, err
	}

	for _, m := range s.members {
		if m.TenantID == tenantID && m.Email == cleanEmail {
			return nil, ErrMemberAlreadyExists
		}
	}

	now := time.Now().Unix()
	m := &Member{
		MemberID:  GenerateMemberID(),
		TenantID:  tenantID,
		Email:     cleanEmail,
		Role:      role,
		Status:    MemberStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.members[m.MemberID] = m

	s.recordAudit(tenantID, actorMemberID, "member.created", "Member", m.MemberID, nil, map[string]interface{}{"email": cleanEmail, "role": string(role)}, "127.0.0.1")
	return m, nil
}

func (s *MemoryService) GetMember(ctx context.Context, tenantID, memberID string) (*Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return nil, ErrMemberNotFound
	}
	return m, nil
}

func (s *MemoryService) ListMembers(ctx context.Context, tenantID string) ([]*Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Member, 0)
	for _, m := range s.members {
		if m.TenantID == tenantID {
			res = append(res, m)
		}
	}
	return res, nil
}

func (s *MemoryService) countActiveOwnersLocked(tenantID string) int {
	activeOwners := 0
	for _, other := range s.members {
		if other.TenantID == tenantID && other.Role == RoleOwner && other.Status == MemberStatusActive {
			activeOwners++
		}
	}
	return activeOwners
}

func (s *MemoryService) UpdateMember(ctx context.Context, tenantID, memberID string, role *MemberRole, status *MemberStatus, actorMemberID string) (*Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return nil, ErrMemberNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberUpdate); err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && (role != nil && *role != RoleOwner || status != nil && *status == MemberStatusDisabled) {
		if s.countActiveOwnersLocked(tenantID) <= 1 {
			return nil, ErrCannotDemoteLastOwner
		}
	}

	before := map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}
	if role != nil {
		m.Role = *role
	}
	if status != nil {
		m.Status = *status
	}
	m.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "member.updated", "Member", memberID, before, map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}, "127.0.0.1")
	return m, nil
}

func (s *MemoryService) RemoveMember(ctx context.Context, tenantID, memberID string, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[memberID]
	if !ok || m.TenantID != tenantID {
		return ErrMemberNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionMemberDelete); err != nil {
		return err
	}
	if m.Role == RoleOwner && s.countActiveOwnersLocked(tenantID) <= 1 {
		return ErrCannotRemoveLastOwner
	}

	delete(s.members, memberID)
	s.recordAudit(tenantID, actorMemberID, "member.deleted", "Member", memberID, map[string]interface{}{"email": m.Email}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Agents & Kill Switch
// ----------------------------------------------------------------------------

