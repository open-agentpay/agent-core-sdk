package admin

import (
	"context"
	"fmt"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
	"github.com/open-agentpay/agent-core-sdk/gateway/wallet"
	"strings"
	"time"
)

func (s *MemoryService) CreateTenant(ctx context.Context, name string, tenantID string, ownerEmail string, currency ...string) (*Tenant, *Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, nil, fmt.Errorf("tenant name cannot be empty")
	}

	rawCurr := ""
	if len(currency) > 0 {
		rawCurr = strings.TrimSpace(currency[0])
	}
	curr, err := NormalizeCurrency(rawCurr)
	if err != nil {
		return nil, nil, err
	}

	for _, t := range s.tenants {
		if t.Name == cleanName {
			return nil, nil, ErrTenantAlreadyExists
		}
	}

	tid := tenantID
	if tid == "" {
		tid = GenerateTenantID()
	}

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

	var ownerMember *Member
	if ownerEmail != "" {
		ownerMember = &Member{
			MemberID:  GenerateMemberID(),
			TenantID:  tid,
			Email:     strings.TrimSpace(ownerEmail),
			Role:      RoleOwner,
			Status:    MemberStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
		s.members[ownerMember.MemberID] = ownerMember
	}

	s.initMasterWalletLocked(tid, curr)
	s.recordAudit(tid, "system", "tenant.created", "Tenant", tid, nil, map[string]interface{}{"name": cleanName, "currency": curr}, "127.0.0.1")
	return t, ownerMember, nil
}

func (s *MemoryService) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if t.Currency == "" {
		t.Currency = "USD"
	}
	return t, nil
}

func (s *MemoryService) ListTenants(ctx context.Context) ([]*Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		if t.Currency == "" {
			t.Currency = "USD"
		}
		res = append(res, t)
	}
	return res, nil
}

func (s *MemoryService) UpdateTenant(ctx context.Context, tenantID string, name string, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	before := map[string]interface{}{"name": t.Name}
	t.Name = cleanName
	t.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "tenant.updated", "Tenant", tenantID, before, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return t, nil
}

func (s *MemoryService) UpdateTenantCurrency(ctx context.Context, tenantID string, currency string, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	curr, err := NormalizeCurrency(strings.TrimSpace(currency))
	if err != nil {
		return nil, err
	}

	for _, r := range s.routes {
		if r.TenantID == tenantID {
			return nil, ErrCurrencyLocked
		}
	}
	if s.walletSvc != nil {
		wlt, err := s.walletSvc.GetWalletByTenant(ctx, tenantID)
		if err == nil && wlt != nil {
			entries, _ := s.walletSvc.GetLedgerEntries(ctx, wlt.WalletID)
			if len(entries) > 0 {
				return nil, ErrCurrencyLocked
			}
		}
	}

	before := map[string]interface{}{"currency": t.Currency}
	t.Currency = curr
	t.UpdatedAt = time.Now().Unix()

	if s.walletSvc != nil {
		if memWlt, ok := s.walletSvc.(*wallet.MemoryService); ok {
			if wlt, err := memWlt.GetWalletByTenant(ctx, tenantID); err == nil && wlt != nil {
				wlt.Asset = curr
				wlt.UpdatedAt = time.Now()
			}
		}
	}

	s.recordAudit(tenantID, actorMemberID, "tenant.currency.updated", "Tenant", tenantID, before, map[string]interface{}{"currency": curr}, "127.0.0.1")
	return t, nil
}

func (s *MemoryService) UpdateTenantStatus(ctx context.Context, tenantID string, status TenantStatus, actorMemberID string) (*Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if t.Status == TenantStatusTerminated && status != TenantStatusTerminated {
		return nil, ErrInvalidStatusTransition
	}
	if actorMemberID == "" {
		if !auth.IsSystemContext(ctx) {
			return nil, ErrPermissionDenied
		}
	} else {
		actor, ok := s.members[actorMemberID]
		if !ok || actor.TenantID != tenantID || actor.Role != RoleOwner {
			return nil, ErrPermissionDenied
		}
	}

	before := map[string]interface{}{"status": string(t.Status)}
	t.Status = status
	t.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "tenant.status.changed", "Tenant", tenantID, before, map[string]interface{}{"status": string(status)}, "127.0.0.1")
	return t, nil
}

// ----------------------------------------------------------------------------
// Projects
// ----------------------------------------------------------------------------

func (s *MemoryService) CreateProject(ctx context.Context, tenantID, name string, departmentID *string, budgetCap int64, projectID string, actorMemberID string) (*Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenant, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	if tenant.Status == TenantStatusSuspended {
		return nil, ErrTenantSuspended
	}
	if tenant.Status == TenantStatusTerminated {
		return nil, ErrTenantTerminated
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectCreate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("project name cannot be empty")
	}
	for _, p := range s.projects {
		if p.TenantID == tenantID && p.Name == cleanName {
			return nil, ErrProjectAlreadyExists
		}
	}

	pid := projectID
	if pid == "" {
		pid = GenerateProjectID()
	}

	var deptIDToSet *string
	if departmentID != nil && strings.TrimSpace(*departmentID) != "" {
		d := strings.TrimSpace(*departmentID)
		deptIDToSet = &d
	}

	now := time.Now().Unix()
	p := &Project{
		ProjectID:          pid,
		TenantID:           tenantID,
		DepartmentID:       deptIDToSet,
		Name:               cleanName,
		BudgetCapBaseUnits: budgetCap,
		Status:             ProjectStatusActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	s.projects[pid] = p

	s.recordAudit(tenantID, actorMemberID, "project.created", "Project", pid, nil, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return p, nil
}

func (s *MemoryService) GetProject(ctx context.Context, tenantID, projectID string) (*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.projects[projectID]
	if !ok {
		return nil, ErrProjectNotFound
	}
	if tenantID != "" && p.TenantID != tenantID {
		return nil, ErrProjectTenantMismatch
	}
	return p, nil
}

func (s *MemoryService) ListProjects(ctx context.Context, tenantID string) ([]*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*Project, 0)
	for _, p := range s.projects {
		if tenantID == "" || p.TenantID == tenantID {
			res = append(res, p)
		}
	}
	return res, nil
}

func (s *MemoryService) UpdateProject(ctx context.Context, tenantID, projectID string, name string, departmentID *string, budgetCap *int64, status *ProjectStatus, actorMemberID string) (*Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.projects[projectID]
	if !ok {
		return nil, ErrProjectNotFound
	}
	if p.TenantID != tenantID {
		return nil, ErrProjectTenantMismatch
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectUpdate); err != nil {
		return nil, err
	}

	before := map[string]interface{}{"name": p.Name, "budget_cap": p.BudgetCapBaseUnits, "status": string(p.Status), "department_id": p.DepartmentID}
	if name != "" {
		cleanName := strings.TrimSpace(name)
		for _, other := range s.projects {
			if other.ProjectID != projectID && other.TenantID == tenantID && other.Name == cleanName {
				return nil, ErrProjectAlreadyExists
			}
		}
		p.Name = cleanName
	}
	if departmentID != nil {
		if *departmentID == "" {
			p.DepartmentID = nil
		} else {
			cleanDept := strings.TrimSpace(*departmentID)
			p.DepartmentID = &cleanDept
		}
	}
	if budgetCap != nil {
		p.BudgetCapBaseUnits = *budgetCap
	}
	if status != nil {
		p.Status = *status
	}
	p.UpdatedAt = time.Now().Unix()

	s.recordAudit(tenantID, actorMemberID, "project.updated", "Project", projectID, before, map[string]interface{}{"name": p.Name, "status": string(p.Status), "department_id": p.DepartmentID}, "127.0.0.1")
	return p, nil
}

func (s *MemoryService) DeleteProject(ctx context.Context, tenantID, projectID string, actorMemberID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.projects[projectID]
	if !ok {
		return ErrProjectNotFound
	}
	if p.TenantID != tenantID {
		return ErrProjectTenantMismatch
	}
	if err := s.checkPermissionLocked(tenantID, actorMemberID, PermissionProjectDelete); err != nil {
		return err
	}

	delete(s.projects, projectID)
	s.recordAudit(tenantID, actorMemberID, "project.deleted", "Project", projectID, map[string]interface{}{"name": p.Name}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Members & RBAC
// ----------------------------------------------------------------------------

