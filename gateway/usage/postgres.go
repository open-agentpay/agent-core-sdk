package usage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// PostgresService implements the Service interface backed by PostgreSQL 15+.
type PostgresService struct {
	db *sql.DB
}

// NewPostgresService creates an initialized PostgresService.
func NewPostgresService(db *sql.DB) *PostgresService {
	return &PostgresService{db: db}
}

// RecordRequest inserts an immutable request record into ap_request_record.
func (p *PostgresService) RecordRequest(ctx context.Context, record *RequestRecord) error {
	if record == nil {
		return errors.New("record cannot be nil")
	}
	if record.RequestID == "" {
		record.RequestID = GenerateRequestID()
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO ap_request_record (
			request_id, tenant_id, project_id, api_key_id, agent_id, route_id, config_version,
			client_ip, http_method, request_path, status_code, duration_ms, error_code, is_replay, intent_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (request_id) DO NOTHING;
	`

	nullStr := func(s string) sql.NullString {
		return sql.NullString{String: s, Valid: s != ""}
	}

	_, err := p.db.ExecContext(ctx, query,
		record.RequestID,
		record.TenantID,
		record.ProjectID,
		nullStr(record.APIKeyID),
		nullStr(record.AgentID),
		nullStr(record.RouteID),
		nullStr(record.ConfigVersion),
		record.ClientIP,
		record.HTTPMethod,
		record.RequestPath,
		record.StatusCode,
		record.DurationMs,
		nullStr(record.ErrorCode),
		record.IsReplay,
		nullStr(record.IntentID),
		record.CreatedAt,
	)
	return err
}

// RecordUsage inserts an immutable usage metering record into ap_usage_event.
func (p *PostgresService) RecordUsage(ctx context.Context, event *UsageEvent) error {
	if event == nil {
		return errors.New("usage event cannot be nil")
	}
	if event.EventID == "" {
		event.EventID = GenerateUsageEventID()
	}
	if event.Asset == "" {
		event.Asset = "USDC"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO ap_usage_event (
			event_id, tenant_id, project_id, agent_id, route_id, intent_id,
			amount_base_units, asset, payment_method, is_success, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (event_id) DO NOTHING;
	`

	nullStr := func(s string) sql.NullString {
		return sql.NullString{String: s, Valid: s != ""}
	}

	_, err := p.db.ExecContext(ctx, query,
		event.EventID,
		event.TenantID,
		event.ProjectID,
		nullStr(event.AgentID),
		event.RouteID,
		event.IntentID,
		event.AmountBaseUnits,
		event.Asset,
		event.PaymentMethod,
		event.IsSuccess,
		event.CreatedAt,
	)
	return err
}

// ListRequestRecords retrieves request records with dynamic SQL filtering and pagination.
func (p *PostgresService) ListRequestRecords(ctx context.Context, filter RequestFilter) ([]*RequestRecord, int64, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", idx))
		args = append(args, filter.TenantID)
		idx++
	}
	if filter.ProjectID != "" {
		conditions = append(conditions, fmt.Sprintf("project_id = $%d", idx))
		args = append(args, filter.ProjectID)
		idx++
	}
	if filter.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", idx))
		args = append(args, filter.AgentID)
		idx++
	}
	if filter.RouteID != "" {
		conditions = append(conditions, fmt.Sprintf("route_id = $%d", idx))
		args = append(args, filter.RouteID)
		idx++
	}
	if filter.StatusCode != 0 {
		conditions = append(conditions, fmt.Sprintf("status_code = $%d", idx))
		args = append(args, filter.StatusCode)
		idx++
	}
	if filter.IsReplay != nil {
		conditions = append(conditions, fmt.Sprintf("is_replay = $%d", idx))
		args = append(args, *filter.IsReplay)
		idx++
	}
	if filter.StartTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.StartTime)
		idx++
	}
	if filter.EndTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.EndTime)
		idx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// 1. Total Count Query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ap_request_record %s;", whereClause)
	var total int64
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count request records: %w", err)
	}

	// 2. Paginated Data Query
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT request_id, tenant_id, project_id, api_key_id, agent_id, route_id, config_version,
		       client_ip, http_method, request_path, status_code, duration_ms, error_code, is_replay, intent_id, created_at
		FROM ap_request_record
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d;
	`, whereClause, idx, idx+1)

	args = append(args, limit, offset)
	rows, err := p.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query request records: %w", err)
	}
	defer rows.Close()

	var records []*RequestRecord
	for rows.Next() {
		var (
			rec           RequestRecord
			apiKeyID      sql.NullString
			agentID       sql.NullString
			routeID       sql.NullString
			configVersion sql.NullString
			errorCode     sql.NullString
			intentID      sql.NullString
		)

		err := rows.Scan(
			&rec.RequestID,
			&rec.TenantID,
			&rec.ProjectID,
			&apiKeyID,
			&agentID,
			&routeID,
			&configVersion,
			&rec.ClientIP,
			&rec.HTTPMethod,
			&rec.RequestPath,
			&rec.StatusCode,
			&rec.DurationMs,
			&errorCode,
			&rec.IsReplay,
			&intentID,
			&rec.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan request record: %w", err)
		}

		if apiKeyID.Valid {
			rec.APIKeyID = apiKeyID.String
		}
		if agentID.Valid {
			rec.AgentID = agentID.String
		}
		if routeID.Valid {
			rec.RouteID = routeID.String
		}
		if configVersion.Valid {
			rec.ConfigVersion = configVersion.String
		}
		if errorCode.Valid {
			rec.ErrorCode = errorCode.String
		}
		if intentID.Valid {
			rec.IntentID = intentID.String
		}

		records = append(records, &rec)
	}

	return records, total, rows.Err()
}

// ListUsageEvents retrieves usage events with dynamic filtering and pagination.
func (p *PostgresService) ListUsageEvents(ctx context.Context, filter UsageFilter) ([]*UsageEvent, int64, error) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", idx))
		args = append(args, filter.TenantID)
		idx++
	}
	if filter.ProjectID != "" {
		conditions = append(conditions, fmt.Sprintf("project_id = $%d", idx))
		args = append(args, filter.ProjectID)
		idx++
	}
	if filter.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", idx))
		args = append(args, filter.AgentID)
		idx++
	}
	if filter.RouteID != "" {
		conditions = append(conditions, fmt.Sprintf("route_id = $%d", idx))
		args = append(args, filter.RouteID)
		idx++
	}
	if filter.IntentID != "" {
		conditions = append(conditions, fmt.Sprintf("intent_id = $%d", idx))
		args = append(args, filter.IntentID)
		idx++
	}
	if filter.PaymentMethod != "" {
		conditions = append(conditions, fmt.Sprintf("payment_method = $%d", idx))
		args = append(args, filter.PaymentMethod)
		idx++
	}
	if filter.IsSuccess != nil {
		conditions = append(conditions, fmt.Sprintf("is_success = $%d", idx))
		args = append(args, *filter.IsSuccess)
		idx++
	}
	if filter.StartTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.StartTime)
		idx++
	}
	if filter.EndTime != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.EndTime)
		idx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ap_usage_event %s;", whereClause)
	var total int64
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count usage events: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT event_id, tenant_id, project_id, agent_id, route_id, intent_id,
		       amount_base_units, asset, payment_method, is_success, created_at
		FROM ap_usage_event
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d;
	`, whereClause, idx, idx+1)

	args = append(args, limit, offset)
	rows, err := p.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query usage events: %w", err)
	}
	defer rows.Close()

	var events []*UsageEvent
	for rows.Next() {
		var (
			evt     UsageEvent
			agentID sql.NullString
		)

		err := rows.Scan(
			&evt.EventID,
			&evt.TenantID,
			&evt.ProjectID,
			&agentID,
			&evt.RouteID,
			&evt.IntentID,
			&evt.AmountBaseUnits,
			&evt.Asset,
			&evt.PaymentMethod,
			&evt.IsSuccess,
			&evt.CreatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan usage event: %w", err)
		}

		if agentID.Valid {
			evt.AgentID = agentID.String
		}

		events = append(events, &evt)
	}

	return events, total, rows.Err()
}

// GetRequestRecord returns a specific request record by ID with tenant boundary validation.
func (p *PostgresService) GetRequestRecord(ctx context.Context, tenantID, requestID string) (*RequestRecord, error) {
	query := `
		SELECT request_id, tenant_id, project_id, api_key_id, agent_id, route_id, config_version,
		       client_ip, http_method, request_path, status_code, duration_ms, error_code, is_replay, intent_id, created_at
		FROM ap_request_record
		WHERE request_id = $1
		LIMIT 1;
	`
	var (
		rec           RequestRecord
		apiKeyID      sql.NullString
		agentID       sql.NullString
		routeID       sql.NullString
		configVersion sql.NullString
		errorCode     sql.NullString
		intentID      sql.NullString
	)

	err := p.db.QueryRowContext(ctx, query, requestID).Scan(
		&rec.RequestID,
		&rec.TenantID,
		&rec.ProjectID,
		&apiKeyID,
		&agentID,
		&routeID,
		&configVersion,
		&rec.ClientIP,
		&rec.HTTPMethod,
		&rec.RequestPath,
		&rec.StatusCode,
		&rec.DurationMs,
		&errorCode,
		&rec.IsReplay,
		&intentID,
		&rec.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRequestRecordNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request record: %w", err)
	}

	if apiKeyID.Valid {
		rec.APIKeyID = apiKeyID.String
	}
	if agentID.Valid {
		rec.AgentID = agentID.String
	}
	if routeID.Valid {
		rec.RouteID = routeID.String
	}
	if configVersion.Valid {
		rec.ConfigVersion = configVersion.String
	}
	if errorCode.Valid {
		rec.ErrorCode = errorCode.String
	}
	if intentID.Valid {
		rec.IntentID = intentID.String
	}

	if tenantID != "" && rec.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return &rec, nil
}

// GetUsageEvent returns a specific usage event by ID with tenant boundary validation.
func (p *PostgresService) GetUsageEvent(ctx context.Context, tenantID, eventID string) (*UsageEvent, error) {
	query := `
		SELECT event_id, tenant_id, project_id, agent_id, route_id, intent_id,
		       amount_base_units, asset, payment_method, is_success, created_at
		FROM ap_usage_event
		WHERE event_id = $1
		LIMIT 1;
	`
	var (
		evt     UsageEvent
		agentID sql.NullString
	)

	err := p.db.QueryRowContext(ctx, query, eventID).Scan(
		&evt.EventID,
		&evt.TenantID,
		&evt.ProjectID,
		&agentID,
		&evt.RouteID,
		&evt.IntentID,
		&evt.AmountBaseUnits,
		&evt.Asset,
		&evt.PaymentMethod,
		&evt.IsSuccess,
		&evt.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUsageEventNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get usage event: %w", err)
	}

	if agentID.Valid {
		evt.AgentID = agentID.String
	}

	if tenantID != "" && evt.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return &evt, nil
}
