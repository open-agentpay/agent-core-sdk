package timeline

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-agentpay/agent-core-sdk/gateway/agent"
)

// PostgresService implements persistent storage and read model indexing in PostgreSQL (T5.8).
type PostgresService struct {
	db *sql.DB
}

// NewPostgresService creates a new Postgres-backed timeline service.
func NewPostgresService(db *sql.DB) *PostgresService {
	return &PostgresService{db: db}
}

// RecordEvent stores an immutable audit event in the ap_agent_audit_event table.
func (p *PostgresService) RecordEvent(ctx context.Context, event *agent.AuditEvent) error {
	if event == nil {
		return nil
	}

	dataBytes, err := json.Marshal(event.Data)
	if err != nil {
		dataBytes = []byte("{}")
	}

	var sessionID, taskID, toolName, parentReqID string
	if event.Declared != nil {
		sessionID = event.Declared.SessionID
		taskID = event.Declared.TaskID
		toolName = event.Declared.ToolName
		parentReqID = event.Declared.ParentRequestID
	}

	var occurredAt time.Time
	if event.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, event.Timestamp); err == nil {
			occurredAt = t
		} else if t, err := time.Parse(time.RFC3339, event.Timestamp); err == nil {
			occurredAt = t
		} else {
			occurredAt = time.Now()
		}
	} else {
		occurredAt = time.Now()
	}

	summary := GenerateSummary(event)

	query := `
		INSERT INTO ap_agent_audit_event (
			event_id, event_type, version, occurred_at, tenant_id, project_id, agent_id,
			request_id, idempotency_key, intent_id, hold_id, settlement_id, fulfillment_id,
			actor_type, actor_id, client_ip, user_agent,
			session_id, task_id, tool_name, parent_request_id, summary, data
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, NULLIF($9, ''), NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''),
			$14, $15, $16, NULLIF($17, ''),
			NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''), NULLIF($21, ''), $22, $23
		)
		ON CONFLICT (event_id) DO NOTHING
	`

	_, err = p.db.ExecContext(ctx, query,
		event.EventID,
		event.EventType,
		event.Version,
		occurredAt,
		event.TenantID,
		event.ProjectID,
		event.AgentID,
		event.Correlation.RequestID,
		event.Correlation.IdempotencyKey,
		event.Correlation.IntentID,
		event.Correlation.HoldID,
		event.Correlation.SettlementID,
		event.Correlation.FulfillmentID,
		event.Actor.Type,
		event.Actor.ID,
		event.Actor.ClientIP,
		event.Actor.UserAgent,
		sessionID,
		taskID,
		toolName,
		parentReqID,
		summary,
		string(dataBytes),
	)
	return err
}

// GetTimeline retrieves paginated and filtered timeline events from PostgreSQL.
func (p *PostgresService) GetTimeline(ctx context.Context, tenantID, agentID string, filter TimelineFilter) ([]*TimelineEvent, int64, []string, error) {
	// 1. Query distinct sessions for this agent under the tenant
	sessionQuery := `
		SELECT DISTINCT session_id
		FROM ap_agent_audit_event
		WHERE tenant_id = $1 AND agent_id = $2 AND session_id IS NOT NULL AND session_id <> ''
		ORDER BY session_id ASC
	`
	sRows, err := p.db.QueryContext(ctx, sessionQuery, tenantID, agentID)
	sessions := make([]string, 0)
	if err == nil {
		defer sRows.Close()
		for sRows.Next() {
			var s string
			if err := sRows.Scan(&s); err == nil && s != "" {
				sessions = append(sessions, s)
			}
		}
	}

	// 2. Build dynamic filter query
	var whereClauses []string
	var args []interface{}
	argIdx := 1

	whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", argIdx))
	args = append(args, tenantID)
	argIdx++

	whereClauses = append(whereClauses, fmt.Sprintf("agent_id = $%d", argIdx))
	args = append(args, agentID)
	argIdx++

	if filter.ProjectID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("project_id = $%d", argIdx))
		args = append(args, filter.ProjectID)
		argIdx++
	}

	if filter.SessionID != "" && filter.SessionID != "all" {
		whereClauses = append(whereClauses, fmt.Sprintf("session_id = $%d", argIdx))
		args = append(args, filter.SessionID)
		argIdx++
	}

	if filter.TaskID != "" && filter.TaskID != "all" {
		whereClauses = append(whereClauses, fmt.Sprintf("task_id = $%d", argIdx))
		args = append(args, filter.TaskID)
		argIdx++
	}

	if filter.EventType != "" && filter.EventType != "all" {
		whereClauses = append(whereClauses, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, filter.EventType)
		argIdx++
	}

	if filter.StartTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at >= $%d", argIdx))
		args = append(args, *filter.StartTime)
		argIdx++
	}

	if filter.EndTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("occurred_at <= $%d", argIdx))
		args = append(args, *filter.EndTime)
		argIdx++
	}

	whereSQL := "WHERE " + strings.Join(whereClauses, " AND ")

	// 3. Count total matching events
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ap_agent_audit_event %s", whereSQL)
	var total int64
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, sessions, err
	}

	if total == 0 {
		return []*TimelineEvent{}, 0, sessions, nil
	}

	// 4. Select paginated items
	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT
			event_id, event_type, occurred_at, actor_type, summary,
			tenant_id, project_id, agent_id, request_id,
			COALESCE(intent_id, ''), COALESCE(settlement_id, ''), COALESCE(hold_id, ''),
			COALESCE(session_id, ''), COALESCE(task_id, ''), COALESCE(tool_name, ''), COALESCE(parent_request_id, ''),
			data
		FROM ap_agent_audit_event
		%s
		ORDER BY occurred_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := p.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, sessions, err
	}
	defer rows.Close()

	items := make([]*TimelineEvent, 0)
	for rows.Next() {
		var (
			eventID, eventType, actorType, summary                                           string
			occurredAt                                                                       time.Time
			tID, pID, aID, reqID, intentID, settlementID, holdID                             string
			sessionIDVal, taskIDVal, toolNameVal, parentReqIDVal                             string
			dataBytes                                                                        []byte
		)

		err := rows.Scan(
			&eventID, &eventType, &occurredAt, &actorType, &summary,
			&tID, &pID, &aID, &reqID,
			&intentID, &settlementID, &holdID,
			&sessionIDVal, &taskIDVal, &toolNameVal, &parentReqIDVal,
			&dataBytes,
		)
		if err != nil {
			return nil, 0, sessions, err
		}

		var dataMap map[string]interface{}
		if len(dataBytes) > 0 {
			_ = json.Unmarshal(dataBytes, &dataMap)
		}

		observed := ObservedFacts{
			TenantID:        tID,
			ProjectID:       pID,
			AgentID:         aID,
			RequestID:       reqID,
			PaymentIntentID: intentID,
			SettlementID:    settlementID,
			HoldID:          holdID,
		}

		if dataMap != nil {
			if rID, ok := dataMap["route_id"].(string); ok {
				observed.RouteID = rID
			}
			if cv, ok := dataMap["config_version"].(string); ok {
				observed.ConfigVersion = cv
			}
			if st, ok := dataMap["http_status"].(float64); ok {
				observed.StatusCode = int(st)
			}
			if lat, ok := dataMap["duration_ms"].(float64); ok {
				observed.LatencyMs = int64(lat)
			}
			if amt, ok := dataMap["amount_base_units"].(float64); ok {
				observed.CostBaseUnits = int64(amt)
			}
			if act, ok := dataMap["action"].(string); ok {
				observed.PolicyDecision = act
			}
			if rc, ok := dataMap["reason_code"].(string); ok {
				observed.RejectCode = rc
			}
			if reqHash, ok := dataMap["request_hash"].(string); ok {
				observed.RequestHash = reqHash
			}
			if opID, ok := dataMap["operator_id"].(string); ok {
				observed.OperatorID = opID
			}
			if cr, ok := dataMap["control_reason"].(string); ok {
				observed.ControlReason = cr
			}
		}

		var declared *agent.DeclaredContext
		if sessionIDVal != "" || taskIDVal != "" || toolNameVal != "" || parentReqIDVal != "" {
			declared = &agent.DeclaredContext{
				SessionID:       sessionIDVal,
				TaskID:          taskIDVal,
				ToolName:        toolNameVal,
				ParentRequestID: parentReqIDVal,
			}
		}

		items = append(items, &TimelineEvent{
			EventID:    eventID,
			EventType:  eventType,
			OccurredAt: occurredAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
			Actor:      actorType,
			Summary:    summary,
			Observed:   observed,
			Declared:   declared,
			Data:       dataMap,
		})
	}

	return items, total, sessions, nil
}
