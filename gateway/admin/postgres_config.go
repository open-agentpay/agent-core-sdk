package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"github.com/open-agentpay/agent-core-sdk/gateway/rcu"
)

func (p *PostgresService) ValidateConfig(ctx context.Context, tenantID string, actorMemberID string) (*ValidationResult, error) {
	if _, err := p.GetTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionRouteRead); err != nil {
		return nil, err
	}

	routes, err := p.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policies, err := p.ListPolicies(ctx, tenantID, "", "")
	if err != nil {
		return nil, err
	}

	res := evaluateConfigValidation(routes, policies)
	// Also enforce Postgres-specific positive timeout check if configured <= 0
	for _, r := range routes {
		if r.TimeoutMs <= 0 {
			res.Errors = append(res.Errors, ValidationError{
				TargetType: "Route",
				TargetID:   r.RouteID,
				Field:      "timeout_ms",
				Code:       "INVALID_TIMEOUT",
				Message:    "超时时间必须大于 0 毫秒",
			})
		}
	}
	for _, pol := range policies {
		if pol.MaxAmountPerRequest <= 0 {
			res.Errors = append(res.Errors, ValidationError{
				TargetType: "Policy",
				TargetID:   pol.PolicyID,
				Field:      "max_amount_per_request",
				Code:       "INVALID_MAX_AMOUNT",
				Message:    "单笔最大支付金额必须大于 0",
			})
		}
	}
	res.Valid = len(res.Errors) == 0
	res.Summary.ErrorCount = len(res.Errors)

	p.mu.Lock()
	p.lastValidation[tenantID] = res
	p.mu.Unlock()

	p.recordAudit(ctx, tenantID, actorMemberID, "config.validated", "Tenant", tenantID, nil, map[string]interface{}{
		"valid":       res.Valid,
		"error_count": len(res.Errors),
	}, "127.0.0.1")

	return res, nil
}

func (p *PostgresService) GetDraftSummary(ctx context.Context, tenantID string) (*ConfigDraftSummary, error) {
	routes, err := p.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policies, err := p.ListPolicies(ctx, tenantID, "", "")
	if err != nil {
		return nil, err
	}

	p.mu.RLock()
	lastRes := p.lastValidation[tenantID]
	p.mu.RUnlock()

	return buildDraftSummary(tenantID, len(routes), len(policies), lastRes), nil
}

func (p *PostgresService) GetDraftDiff(ctx context.Context, tenantID string) (*ConfigDraftDiff, error) {
	routes, err := p.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policies, err := p.ListPolicies(ctx, tenantID, "", "")
	if err != nil {
		return nil, err
	}
	return buildDraftDiff(tenantID, routes, policies), nil
}

func (p *PostgresService) persistNewConfigVersion(ctx context.Context, tenantID, versionID, actorMemberID, summary string, newVersionNumber int64, snap *rcu.ConfigSnapshot) (*ConfigVersion, error) {
	snapBytes, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "UPDATE ap_config_version SET is_active = FALSE WHERE tenant_id = $1 AND is_active = TRUE", tenantID); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ap_config_version (
			version_id, tenant_id, version_number, snapshot_json, published_by, change_summary, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, TRUE, NOW())
	`, versionID, tenantID, newVersionNumber, snapBytes, actorMemberID, summary); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var publisherEmail string
	_ = p.db.QueryRowContext(ctx, "SELECT email FROM ap_member WHERE member_id = $1", actorMemberID).Scan(&publisherEmail)
	if publisherEmail == "" {
		publisherEmail = actorMemberID
	}

	if p.rcuMgr != nil {
		_ = p.rcuMgr.Update(snap)
	}

	return &ConfigVersion{
		VersionID:      versionID,
		TenantID:       tenantID,
		VersionNumber:  newVersionNumber,
		SnapshotJSON:   snap,
		SnapshotHash:   snap.SnapshotHash,
		PublishedBy:    actorMemberID,
		PublisherEmail: publisherEmail,
		ChangeSummary:  summary,
		IsActive:       true,
		RoutesCount:    len(snap.Routes),
		PoliciesCount:  len(snap.Policies),
		CreatedAt:      snap.PublishedAt,
	}, nil
}

func (p *PostgresService) PublishConfig(ctx context.Context, tenantID string, changeSummary string, actorMemberID string) (*ConfigVersion, error) {
	if _, err := p.GetTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	valResult, err := p.ValidateConfig(ctx, tenantID, actorMemberID)
	if err != nil {
		return nil, err
	}
	if !valResult.Valid {
		return nil, ErrConfigValidationFailed
	}

	routes, err := p.ListRoutes(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policies, err := p.ListPolicies(ctx, tenantID, "", "")
	if err != nil {
		return nil, err
	}

	rcuRoutes, rcuPolicies := buildRCUSnapshotConfigs(routes, policies)
	snapshotHash := rcu.ComputeCanonicalSnapshotHash(rcuRoutes, rcuPolicies)

	var maxVerNum int64
	_ = p.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_number), 0) FROM ap_config_version WHERE tenant_id = $1", tenantID).Scan(&maxVerNum)
	newVersionNumber := maxVerNum + 1
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	summary := strings.TrimSpace(changeSummary)
	if summary == "" {
		summary = fmt.Sprintf("Publish configuration version v%d", newVersionNumber)
	}

	snap := &rcu.ConfigSnapshot{
		SchemaVersion: "2.0.0",
		TenantID:      tenantID,
		VersionID:     versionID,
		VersionNumber: newVersionNumber,
		PublishedAt:   now,
		PublishedBy:   actorMemberID,
		ChangeSummary: summary,
		SnapshotHash:  snapshotHash,
		Routes:        rcuRoutes,
		Policies:      rcuPolicies,
	}

	ver, err := p.persistNewConfigVersion(ctx, tenantID, versionID, actorMemberID, summary, newVersionNumber, snap)
	if err != nil {
		return nil, err
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "config.published", "ConfigVersion", versionID, nil, map[string]interface{}{
		"version_number": newVersionNumber,
		"snapshot_hash":  snapshotHash,
		"change_summary": summary,
		"routes_count":   len(rcuRoutes),
		"policies_count": len(rcuPolicies),
	}, "127.0.0.1")

	return ver, nil
}

func scanConfigVersionRow(scanner routeRowScanner) (*ConfigVersion, error) {
	var v ConfigVersion
	var snapBytes []byte
	if err := scanner.Scan(
		&v.VersionID,
		&v.TenantID,
		&v.VersionNumber,
		&snapBytes,
		&v.PublishedBy,
		&v.PublisherEmail,
		&v.ChangeSummary,
		&v.IsActive,
		&v.CreatedAt,
	); err != nil {
		return nil, err
	}
	var snap rcu.ConfigSnapshot
	if err := json.Unmarshal(snapBytes, &snap); err == nil {
		v.SnapshotJSON = &snap
		v.SnapshotHash = snap.SnapshotHash
		v.RoutesCount = len(snap.Routes)
		v.PoliciesCount = len(snap.Policies)
	}
	return &v, nil
}

func (p *PostgresService) ListConfigVersions(ctx context.Context, tenantID string) ([]*ConfigVersion, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT v.version_id, v.tenant_id, v.version_number, v.snapshot_json, v.published_by, COALESCE(m.email, v.published_by), v.change_summary, v.is_active, EXTRACT(EPOCH FROM v.created_at)::BIGINT
		FROM ap_config_version v
		LEFT JOIN ap_member m ON v.published_by = m.member_id
		WHERE v.tenant_id = $1
		ORDER BY v.version_number DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := make([]*ConfigVersion, 0)
	for rows.Next() {
		v, err := scanConfigVersionRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, v)
	}
	return list, nil
}

func (p *PostgresService) GetConfigVersion(ctx context.Context, tenantID, versionID string) (*ConfigVersion, error) {
	v, err := scanConfigVersionRow(p.db.QueryRowContext(ctx, `
		SELECT v.version_id, v.tenant_id, v.version_number, v.snapshot_json, v.published_by, COALESCE(m.email, v.published_by), v.change_summary, v.is_active, EXTRACT(EPOCH FROM v.created_at)::BIGINT
		FROM ap_config_version v
		LEFT JOIN ap_member m ON v.published_by = m.member_id
		WHERE v.tenant_id = $1 AND v.version_id = $2
	`, tenantID, versionID))
	if err != nil {
		return nil, ErrConfigVersionNotFound
	}
	return v, nil
}

func (p *PostgresService) RollbackConfig(ctx context.Context, tenantID, targetVersionID, reason, actorMemberID string) (*ConfigVersion, error) {
	if err := p.enforcePermission(ctx, actorMemberID, tenantID, PermissionRouteWrite); err != nil {
		return nil, err
	}

	targetVer, err := p.GetConfigVersion(ctx, tenantID, targetVersionID)
	if err != nil {
		return nil, err
	}
	if targetVer.IsActive {
		return nil, ErrCannotRollbackToActive
	}

	var maxVerNum int64
	_ = p.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version_number), 0) FROM ap_config_version WHERE tenant_id = $1", tenantID).Scan(&maxVerNum)
	newVersionNumber := maxVerNum + 1
	versionID := GenerateConfigVersionID()
	now := time.Now().Unix()

	restoredSnap, summary := buildRestoredSnapshot(tenantID, versionID, actorMemberID, reason, newVersionNumber, now, targetVer)

	ver, err := p.persistNewConfigVersion(ctx, tenantID, versionID, actorMemberID, summary, newVersionNumber, restoredSnap)
	if err != nil {
		return nil, err
	}

	p.recordAudit(ctx, tenantID, actorMemberID, "config.rolled_back", "ConfigVersion", versionID, map[string]interface{}{
		"target_version_id":     targetVer.VersionID,
		"target_version_number": targetVer.VersionNumber,
	}, map[string]interface{}{
		"new_version_id":     versionID,
		"new_version_number": newVersionNumber,
		"active_hash":        targetVer.SnapshotHash,
		"reason":             reason,
	}, "127.0.0.1")

	return ver, nil
}

func (p *PostgresService) GetConfigVersionDiff(ctx context.Context, tenantID, baseVersionID, targetVersionID string) (*ConfigDraftDiff, error) {
	var baseSnap, targetSnap *rcu.ConfigSnapshot

	if baseVersionID != "" {
		v, err := p.GetConfigVersion(ctx, tenantID, baseVersionID)
		if err != nil {
			return nil, err
		}
		baseSnap = v.SnapshotJSON
	} else {
		var snapBytes []byte
		var activeVerID string
		err := p.db.QueryRowContext(ctx, "SELECT version_id, snapshot_json FROM ap_config_version WHERE tenant_id = $1 AND is_active = TRUE", tenantID).Scan(&activeVerID, &snapBytes)
		if err == nil {
			var s rcu.ConfigSnapshot
			if json.Unmarshal(snapBytes, &s) == nil {
				baseSnap = &s
			}
		}
	}

	if targetVersionID != "" {
		v, err := p.GetConfigVersion(ctx, tenantID, targetVersionID)
		if err != nil {
			return nil, err
		}
		targetSnap = v.SnapshotJSON
	}

	return computeSnapshotDiff(tenantID, baseSnap, targetSnap), nil
}

// ----------------------------------------------------------------------------
// Virtual Wallet Admin
// ----------------------------------------------------------------------------

