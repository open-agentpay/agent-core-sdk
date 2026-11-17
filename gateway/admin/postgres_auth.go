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

func (p *PostgresService) Register(ctx context.Context, tenantName, email, password string, currency ...string) (*Tenant, *Member, error) {
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

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_tenant WHERE name = $1);`, cleanName).Scan(&exists)
	if exists {
		return nil, nil, ErrTenantAlreadyExists
	}
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_member WHERE LOWER(email) = LOWER($1));`, cleanEmail).Scan(&exists)
	if exists {
		return nil, nil, ErrEmailAlreadyRegistered
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	tid := GenerateTenantID()
	mid := GenerateMemberID()
	now := time.Now()
	nowUnix := now.Unix()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ap_tenant (tenant_id, name, currency, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', $4, $4);
	`, tid, cleanName, curr, now); err != nil {
		return nil, nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ap_member (member_id, tenant_id, email, password_hash, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'owner', 'active', $5, $5);
	`, mid, tid, cleanEmail, hash, now); err != nil {
		return nil, nil, fmt.Errorf("failed to create owner member: %w", err)
	}

	walletID := fmt.Sprintf("wlt_%s", tid)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ap_wallet (wallet_id, tenant_id, asset, status, version, available_cache, held_cache, created_at, updated_at)
		VALUES ($1, $2, $3, 'active', 1, 0, 0, $4, $4)
		ON CONFLICT (tenant_id) DO NOTHING;
	`, walletID, tid, curr, now); err != nil {
		return nil, nil, fmt.Errorf("failed to initialize wallet: %w", err)
	}

	auditID := GenerateAuditID()
	_, _ = tx.ExecContext(ctx, `
		INSERT INTO ap_audit_event (audit_id, tenant_id, operator_id, action, target_type, target_id, after_state, client_ip, created_at)
		VALUES ($1, $2, $3, 'auth.register', 'Tenant', $2, $4, '127.0.0.1', $5);
	`, auditID, tid, mid, `{"name":"`+cleanName+`","email":"`+cleanEmail+`","currency":"`+curr+`"}`, now)

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
	m := &Member{
		MemberID:     mid,
		TenantID:     tid,
		Email:        cleanEmail,
		PasswordHash: hash,
		Role:         RoleOwner,
		Status:       MemberStatusActive,
		CreatedAt:    nowUnix,
		UpdatedAt:    nowUnix,
	}
	return t, m, nil
}

func (p *PostgresService) queryMemberAndTenantByEmail(ctx context.Context, email string) (*Member, *Tenant, error) {
	cleanEmail := strings.TrimSpace(email)
	var m Member
	var t Tenant
	var pwd sql.NullString
	err := p.db.QueryRowContext(ctx, `
		SELECT m.member_id, m.tenant_id, m.email, m.password_hash, m.role, m.status,
		       EXTRACT(EPOCH FROM m.created_at)::bigint, EXTRACT(EPOCH FROM m.updated_at)::bigint,
		       t.name, t.currency, t.status, EXTRACT(EPOCH FROM t.created_at)::bigint, EXTRACT(EPOCH FROM t.updated_at)::bigint
		FROM ap_member m
		JOIN ap_tenant t ON m.tenant_id = t.tenant_id
		WHERE LOWER(m.email) = LOWER($1);
	`, cleanEmail).Scan(
		&m.MemberID, &m.TenantID, &m.Email, &pwd, &m.Role, &m.Status, &m.CreatedAt, &m.UpdatedAt,
		&t.Name, &t.Currency, &t.Status, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, nil, err
	}
	t.TenantID = m.TenantID
	if t.Currency == "" {
		t.Currency = "USD"
	}
	if pwd.Valid {
		m.PasswordHash = pwd.String
	}
	return &m, &t, nil
}

func (p *PostgresService) Login(ctx context.Context, email, password string) (*Member, *Tenant, error) {
	if strings.TrimSpace(email) == "" || password == "" {
		return nil, nil, ErrInvalidCredentials
	}
	m, t, err := p.queryMemberAndTenantByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, err
	}
	if m.Status == MemberStatusDisabled {
		return nil, nil, ErrMemberDisabled
	}
	if t.Status == TenantStatusTerminated {
		return nil, nil, ErrTenantTerminated
	}
	if t.Status == TenantStatusSuspended {
		return nil, nil, ErrTenantSuspended
	}
	if m.PasswordHash == "" || !auth.VerifyPassword(password, m.PasswordHash) {
		return nil, nil, ErrInvalidCredentials
	}
	p.recordAudit(ctx, t.TenantID, m.MemberID, "auth.login", "Member", m.MemberID, nil, map[string]interface{}{"email": m.Email}, "127.0.0.1")
	return m, t, nil
}

func (p *PostgresService) GetMemberByEmail(ctx context.Context, email string) (*Member, *Tenant, error) {
	m, t, err := p.queryMemberAndTenantByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrMemberNotFound
	}
	return m, t, err
}

func (p *PostgresService) SetMemberPassword(ctx context.Context, tenantID, memberID, password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	res, err := p.db.ExecContext(ctx, `
		UPDATE ap_member
		SET password_hash = $1, updated_at = NOW()
		WHERE tenant_id = $2 AND member_id = $3;
	`, hash, tenantID, memberID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrMemberNotFound
	}
	return nil
}

// ----------------------------------------------------------------------------
// Tenants
// ----------------------------------------------------------------------------

func (p *PostgresService) AddMember(ctx context.Context, tenantID, email string, role MemberRole, actorMemberID string) (*Member, error) {
	cleanEmail := strings.TrimSpace(strings.ToLower(email))
	if cleanEmail == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionMemberCreate); err != nil {
		return nil, err
	}

	var exists bool
	_ = p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ap_member WHERE tenant_id = $1 AND email = $2);`, tenantID, cleanEmail).Scan(&exists)
	if exists {
		return nil, ErrMemberAlreadyExists
	}

	mid := GenerateMemberID()
	now := time.Now()
	nowUnix := now.Unix()

	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_member (member_id, tenant_id, email, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'active', $5, $5);
	`, mid, tenantID, cleanEmail, string(role), now); err != nil {
		return nil, err
	}

	m := &Member{
		MemberID:  mid,
		TenantID:  tenantID,
		Email:     cleanEmail,
		Role:      role,
		Status:    MemberStatusActive,
		CreatedAt: nowUnix,
		UpdatedAt: nowUnix,
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "member.added", "Member", mid, nil, map[string]interface{}{"email": cleanEmail, "role": string(role)}, "127.0.0.1")
	return m, nil
}

func (p *PostgresService) GetMember(ctx context.Context, tenantID, memberID string) (*Member, error) {
	return p.getMember(ctx, tenantID, memberID)
}

func (p *PostgresService) ListMembers(ctx context.Context, tenantID string) ([]*Member, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT member_id, tenant_id, email, password_hash, role, status,
		       EXTRACT(EPOCH FROM created_at)::bigint, EXTRACT(EPOCH FROM updated_at)::bigint
		FROM ap_member
		WHERE tenant_id = $1
		ORDER BY created_at ASC;
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := make([]*Member, 0)
	for rows.Next() {
		var m Member
		var pwd sql.NullString
		if err := rows.Scan(&m.MemberID, &m.TenantID, &m.Email, &pwd, &m.Role, &m.Status, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		if pwd.Valid {
			m.PasswordHash = pwd.String
		}
		members = append(members, &m)
	}
	return members, nil
}

func (p *PostgresService) countActiveOwners(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := p.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM ap_member WHERE tenant_id = $1 AND role = 'owner' AND status = 'active';
	`, tenantID).Scan(&count)
	return count, err
}

func (p *PostgresService) UpdateMember(ctx context.Context, tenantID, memberID string, role *MemberRole, status *MemberStatus, actorMemberID string) (*Member, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionMemberUpdate); err != nil {
		return nil, err
	}

	m, err := p.getMember(ctx, tenantID, memberID)
	if err != nil {
		return nil, err
	}

	if m.Role == RoleOwner && m.Status == MemberStatusActive {
		activeOwners, err := p.countActiveOwners(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if activeOwners <= 1 {
			if role != nil && *role != RoleOwner {
				return nil, ErrCannotDemoteLastOwner
			}
			if status != nil && *status == MemberStatusDisabled {
				return nil, ErrCannotRemoveLastOwner
			}
		}
	}

	before := map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}
	if role != nil {
		m.Role = *role
	}
	if status != nil {
		m.Status = *status
	}

	if _, err := p.db.ExecContext(ctx, `
		UPDATE ap_member SET role = $1, status = $2, updated_at = NOW() WHERE member_id = $3;
	`, string(m.Role), string(m.Status), memberID); err != nil {
		return nil, err
	}

	m.UpdatedAt = time.Now().Unix()
	p.recordAudit(ctx, tenantID, actorMemberID, "member.updated", "Member", memberID, before, map[string]interface{}{"role": string(m.Role), "status": string(m.Status)}, "127.0.0.1")
	return m, nil
}

func (p *PostgresService) RemoveMember(ctx context.Context, tenantID, memberID string, actorMemberID string) error {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionMemberDelete); err != nil {
		return err
	}
	m, err := p.getMember(ctx, tenantID, memberID)
	if err != nil {
		return err
	}

	if m.Role == RoleOwner && m.Status == MemberStatusActive {
		activeOwners, err := p.countActiveOwners(ctx, tenantID)
		if err != nil {
			return err
		}
		if activeOwners <= 1 {
			return ErrCannotRemoveLastOwner
		}
	}

	if _, err := p.db.ExecContext(ctx, `DELETE FROM ap_member WHERE member_id = $1;`, memberID); err != nil {
		return err
	}
	p.recordAudit(ctx, tenantID, actorMemberID, "member.removed", "Member", memberID, map[string]interface{}{"email": m.Email}, nil, "127.0.0.1")
	return nil
}

// ----------------------------------------------------------------------------
// Agent & Kill Switch
// ----------------------------------------------------------------------------

