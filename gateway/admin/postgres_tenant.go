package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"github.com/open-agentpay/agent-core-sdk/gateway/auth"
)

func (p *PostgresService) CreateTenant(ctx context.Context, name string, tenantID string, ownerEmail string, currency ...string) (*Tenant, *Member, error) {
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

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_tenant WHERE name = $1);`, cleanName).Scan(&exists)
	if exists {
		return nil, nil, ErrTenantAlreadyExists
	}

	tid := tenantID
	if tid == "" {
		tid = GenerateTenantID()
	}

	now := time.Now()
	nowUnix := now.Unix()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ap_tenant (tenant_id, name, currency, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', $4, $4);
	`, tid, cleanName, curr, now); err != nil {
		return nil, nil, err
	}

	var ownerMember *Member
	if ownerEmail != "" {
		cleanOwnerEmail := strings.TrimSpace(ownerEmail)
		mid := GenerateMemberID()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ap_member (member_id, tenant_id, email, role, status, created_at, updated_at)
			VALUES ($1, $2, $3, 'owner', 'active', $4, $4);
		`, mid, tid, cleanOwnerEmail, now); err != nil {
			return nil, nil, err
		}
		ownerMember = &Member{
			MemberID:  mid,
			TenantID:  tid,
			Email:     cleanOwnerEmail,
			Role:      RoleOwner,
			Status:    MemberStatusActive,
			CreatedAt: nowUnix,
			UpdatedAt: nowUnix,
		}
	}

	walletID := fmt.Sprintf("wlt_%s", tid)
	_, _ = tx.ExecContext(ctx, `
		INSERT INTO ap_wallet (wallet_id, tenant_id, asset, status, version, available_cache, held_cache, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', 1, 0, 0, $4, $4)
		ON CONFLICT (tenant_id) DO NOTHING;
	`, walletID, tid, curr, now)

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}

	t := &Tenant{
		TenantID:  tid,
		Name:      cleanName,
		Currency:  curr,
		Status:    TenantStatusActive,
		CreatedAt: nowUnix,
		UpdatedAt: nowUnix,
	}
	p.recordAudit(ctx, tid, "system", "tenant.created", "Tenant", tid, nil, map[string]interface{}{"name": cleanName, "currency": curr}, "127.0.0.1")
	return t, ownerMember, nil
}

func (p *PostgresService) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	var t Tenant
	err := p.db.QueryRowContext(ctx, `
		SELECT tenant_id, name, currency, status, EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_tenant
		WHERE tenant_id = $1;
	`, tenantID).Scan(&t.TenantID, &t.Name, &t.Currency, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTenantNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.Currency == "" {
		t.Currency = "USD"
	}
	return &t, nil
}

func (p *PostgresService) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT tenant_id, name, currency, status, EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_tenant
		ORDER BY created_at DESC;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tenants := make([]*Tenant, 0)
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.TenantID, &t.Name, &t.Currency, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if t.Currency == "" {
			t.Currency = "USD"
		}
		tenants = append(tenants, &t)
	}
	return tenants, nil
}

func (p *PostgresService) UpdateTenant(ctx context.Context, tenantID string, name string, actorMemberID string) (*Tenant, error) {
	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("tenant name cannot be empty")
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	t, err := p.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == TenantStatusTerminated {
		return nil, ErrTenantTerminated
	}

	before := map[string]interface{}{"name": t.Name}
	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_tenant SET name = $1, updated_at = NOW() WHERE tenant_id = $2;
	`, cleanName, tenantID); err != nil {
		return nil, err
	}

	t.Name = cleanName
	t.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "tenant.updated", "Tenant", tenantID, before, map[string]interface{}{"name": cleanName}, "127.0.0.1")
	return t, nil
}

func (p *PostgresService) UpdateTenantCurrency(ctx context.Context, tenantID string, currency string, actorMemberID string) (*Tenant, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionTenantUpdate); err != nil {
		return nil, err
	}

	curr, err := NormalizeCurrency(strings.TrimSpace(currency))
	if err != nil {
		return nil, err
	}

	t, err := p.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == TenantStatusTerminated {
		return nil, ErrTenantTerminated
	}

	var routeCount, ledgerCount int
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ap_route WHERE tenant_id = $1;`, tenantID).Scan(&routeCount)
	_ = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ap_ledger_entry WHERE tenant_id = $1;`, tenantID).Scan(&ledgerCount)
	if routeCount > 0 || ledgerCount > 0 {
		return nil, ErrCurrencyLocked
	}

	before := map[string]interface{}{"currency": t.Currency}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `UPDATE ap_tenant SET currency = $1, updated_at = NOW() WHERE tenant_id = $2;`, curr, tenantID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ap_wallet SET asset = $1, updated_at = NOW() WHERE tenant_id = $2;`, curr, tenantID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	t.Currency = curr
	t.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "tenant.currency.updated", "Tenant", tenantID, before, map[string]interface{}{"currency": curr}, "127.0.0.1")
	return t, nil
}

func (p *PostgresService) UpdateTenantStatus(ctx context.Context, tenantID string, status TenantStatus, actorMemberID string) (*Tenant, error) {
	if actorMemberID == "" {
		if !auth.IsSystemContext(ctx) {
			return nil, ErrPermissionDenied
		}
	} else {
		actor, err := p.getMember(ctx, tenantID, actorMemberID)
		if err != nil || actor.TenantID != tenantID || actor.Role != RoleOwner {
			return nil, ErrPermissionDenied
		}
	}

	t, err := p.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == TenantStatusTerminated && status != TenantStatusTerminated {
		return nil, ErrInvalidStatusTransition
	}

	before := map[string]interface{}{"status": string(t.Status)}
	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_tenant SET status = $1, updated_at = NOW() WHERE tenant_id = $2;
	`, string(status), tenantID); err != nil {
		return nil, err
	}

	t.Status = status
	t.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "tenant.status.changed", "Tenant", tenantID, before, map[string]interface{}{"status": string(status)}, "127.0.0.1")
	return t, nil
}

// ----------------------------------------------------------------------------
// Projects
// ----------------------------------------------------------------------------

func (p *PostgresService) CreateProject(ctx context.Context, tenantID, name string, departmentID *string, budgetCap int64, projectID string, actorMemberID string) (*Project, error) {
	t, err := p.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if t.Status == TenantStatusSuspended {
		return nil, ErrTenantSuspended
	}
	if t.Status == TenantStatusTerminated {
		return nil, ErrTenantTerminated
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionProjectCreate); err != nil {
		return nil, err
	}

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return nil, fmt.Errorf("project name cannot be empty")
	}

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_project WHERE tenant_id = $1 AND name = $2);`, tenantID, cleanName).Scan(&exists)
	if exists {
		return nil, ErrProjectAlreadyExists
	}

	pid := projectID
	if pid == "" {
		pid = GenerateProjectID()
	}

	now := time.Now()
	nowUnix := now.Unix()
	var deptIDToInsert *string
	if departmentID != nil && strings.TrimSpace(*departmentID) != "" {
		d := strings.TrimSpace(*departmentID)
		deptIDToInsert = &d
	}

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_project (project_id, tenant_id, department_id, name, budget_cap_base_units, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'active', $6, $6);
	`, pid, tenantID, deptIDToInsert, cleanName, budgetCap, now); err != nil {
		return nil, err
	}

	prj := &Project{
		ProjectID:          pid,
		TenantID:           tenantID,
		DepartmentID:       deptIDToInsert,
		Name:               cleanName,
		BudgetCapBaseUnits: budgetCap,
		Status:             ProjectStatusActive,
		CreatedAt:          nowUnix,
		UpdatedAt:          nowUnix,
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "project.created", "Project", pid, nil, map[string]interface{}{"name": cleanName, "department_id": deptIDToInsert}, "127.0.0.1")
	return prj, nil
}

func (p *PostgresService) GetProject(ctx context.Context, tenantID, projectID string) (*Project, error) {
	var prj Project
	err := p.db.QueryRowContext(ctx, `
		SELECT project_id, tenant_id, department_id, name, budget_cap_base_units, status,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_project
		WHERE project_id = $1;
	`, projectID).Scan(
		&prj.ProjectID, &prj.TenantID, &prj.DepartmentID, &prj.Name, &prj.BudgetCapBaseUnits, &prj.Status, &prj.CreatedAt, &prj.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, err
	}
	if tenantID != "" && prj.TenantID != tenantID {
		return nil, ErrProjectTenantMismatch
	}
	return &prj, nil
}

func (p *PostgresService) ListProjects(ctx context.Context, tenantID string) ([]*Project, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT project_id, tenant_id, department_id, name, budget_cap_base_units, status,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_project
		WHERE tenant_id = $1
		ORDER BY created_at DESC;
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	projects := make([]*Project, 0)
	for rows.Next() {
		var prj Project
		if err := rows.Scan(&prj.ProjectID, &prj.TenantID, &prj.DepartmentID, &prj.Name, &prj.BudgetCapBaseUnits, &prj.Status, &prj.CreatedAt, &prj.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, &prj)
	}
	return projects, nil
}

func (p *PostgresService) UpdateProject(ctx context.Context, tenantID, projectID string, name string, departmentID *string, budgetCap *int64, status *ProjectStatus, actorMemberID string) (*Project, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionProjectUpdate); err != nil {
		return nil, err
	}

	prj, err := p.GetProject(ctx, tenantID, projectID)
	if err != nil {
		return nil, err
	}

	before := map[string]interface{}{"name": prj.Name, "budget_cap": prj.BudgetCapBaseUnits, "status": string(prj.Status), "department_id": prj.DepartmentID}
	if name != "" {
		cleanName := strings.TrimSpace(name)
		var exists bool
		_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_project WHERE tenant_id = $1 AND name = $2 AND project_id != $3);`, tenantID, cleanName, projectID).Scan(&exists)
		if exists {
			return nil, ErrProjectAlreadyExists
		}
		prj.Name = cleanName
	}
	if departmentID != nil {
		if *departmentID == "" {
			prj.DepartmentID = nil
		} else {
			cleanDept := strings.TrimSpace(*departmentID)
			prj.DepartmentID = &cleanDept
		}
	}
	if budgetCap != nil {
		prj.BudgetCapBaseUnits = *budgetCap
	}
	if status != nil {
		prj.Status = *status
	}

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_project
		SET name = $1, department_id = $2, budget_cap_base_units = $3, status = $4, updated_at = NOW()
		WHERE project_id = $5;
	`, prj.Name, prj.DepartmentID, prj.BudgetCapBaseUnits, string(prj.Status), projectID); err != nil {
		return nil, err
	}

	prj.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "project.updated", "Project", projectID, before, map[string]interface{}{"name": prj.Name, "status": string(prj.Status), "department_id": prj.DepartmentID}, "127.0.0.1")
	return prj, nil
}

func (p *PostgresService) DeleteProject(ctx context.Context, tenantID, projectID string, actorMemberID string) error {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionProjectDelete); err != nil {
		return err
	}
	prj, err := p.GetProject(ctx, tenantID, projectID)
	if err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `DELETE FROM ap_project WHERE project_id = $1;`, projectID); err != nil {
		return err
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "project.deleted", "Project", projectID, map[string]interface{}{"name": prj.Name}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Members
// ----------------------------------------------------------------------------

