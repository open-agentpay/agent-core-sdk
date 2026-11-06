package payment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// PostgresService implements payment.Service with PostgreSQL persistence.
type PostgresService struct {
	db *sql.DB
}

// NewPostgresService creates an instance of PostgresService.
func NewPostgresService(db *sql.DB) *PostgresService {
	if db != nil {
		// Drop foreign key constraint on config_version_id if it exists.
		// Snapshot/sync config versions (e.g. ver_sync_..., ver_default) are runtime dynamic
		// and do not exist in the ap_config_version release table.
		_, _ = db.Exec("ALTER TABLE ap_payment_intent DROP CONSTRAINT IF EXISTS ap_payment_intent_config_version_id_fkey;")
		// Auto-migrate idempotency_key to allow NULL in legacy initialized databases (non-idempotent requests)
		_, _ = db.Exec("ALTER TABLE ap_payment_intent ALTER COLUMN idempotency_key DROP NOT NULL;")
		_, _ = db.Exec("ALTER TABLE ap_wallet_challenge ALTER COLUMN idempotency_key DROP NOT NULL;")
		// Auto-migrate settlement_id column width to VARCHAR(128)
		_, _ = db.Exec("ALTER TABLE ap_settlement_record ALTER COLUMN settlement_id TYPE VARCHAR(128);")
		_, _ = db.Exec("ALTER TABLE ap_settlement_record ADD COLUMN IF NOT EXISTS facilitator_settlement_id VARCHAR(128);")
		_, _ = db.Exec("ALTER TABLE ap_agent_audit_event ALTER COLUMN settlement_id TYPE VARCHAR(128);")
	}
	return &PostgresService{db: db}
}

func (p *PostgresService) CreateWalletChallenge(ctx context.Context, ch *WalletChallenge) error {
	if ch == nil || ch.ChallengeID == "" || ch.IntentID == "" || ch.Amount <= 0 {
		return errors.New("invalid wallet challenge")
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO ap_wallet_challenge (
			challenge_id, tenant_id, wallet_id, api_key_hash, route_id, intent_id, idempotency_key,
			request_binding, amount_base_units, asset, resource_uri, valid_after, valid_before, status
		) VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$13,'issued')
	`, ch.ChallengeID, ch.TenantID, ch.WalletID, ch.APIKeyHash, ch.RouteID, ch.IntentID,
		ch.IdempotencyKey, ch.RequestBinding, ch.Amount, ch.Asset, ch.ResourceURI, ch.ValidAfter, ch.ValidBefore)
	return err
}

// ConsumeWalletChallenge uses a conditional UPDATE as the cross-instance one-time claim.
// SECURITY-REVIEW: only a matching, unexpired issued row can transition to consuming; the
// unique (wallet_id, nonce) constraint prevents nonce reuse across challenge IDs.
func (p *PostgresService) ConsumeWalletChallenge(ctx context.Context, challengeID, tenantID, walletID, apiKeyHash, routeID, requestBinding, nonce, idempotencyKey string, amount int64, now time.Time) (*WalletChallenge, error) {
	var ch WalletChallenge
	err := p.db.QueryRowContext(ctx, `
		UPDATE ap_wallet_challenge
		SET status = 'consuming', nonce = $8, consumed_at = $9
		WHERE challenge_id = $1 AND tenant_id = $2 AND wallet_id = $3 AND api_key_hash = $4
		  AND route_id = $5 AND request_binding = $6 AND amount_base_units = $7
		  AND COALESCE(idempotency_key, '') = $10
		  AND status = 'issued' AND valid_after <= $9 AND valid_before >= $9
		RETURNING challenge_id, tenant_id, wallet_id, api_key_hash, route_id, intent_id,
		          request_binding, amount_base_units, asset, resource_uri, valid_after,
		          valid_before, status, nonce, COALESCE(hold_id, '')
	`, challengeID, tenantID, walletID, apiKeyHash, routeID, requestBinding, amount, nonce, now, idempotencyKey).Scan(
		&ch.ChallengeID, &ch.TenantID, &ch.WalletID, &ch.APIKeyHash, &ch.RouteID, &ch.IntentID,
		&ch.RequestBinding, &ch.Amount, &ch.Asset, &ch.ResourceURI, &ch.ValidAfter,
		&ch.ValidBefore, &ch.Status, &ch.Nonce, &ch.HoldID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrWalletChallengeInvalid
		}
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return nil, ErrWalletChallengeReplay
		}
		return nil, err
	}
	return &ch, nil
}

func (p *PostgresService) SetWalletChallengeHold(ctx context.Context, challengeID, holdID string) error {
	res, err := p.db.ExecContext(ctx, `
		UPDATE ap_wallet_challenge SET hold_id = $1, status = 'consumed'
		WHERE challenge_id = $2 AND status = 'consuming' AND hold_id IS NULL
	`, holdID, challengeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrWalletChallengeInvalid
	}
	return nil
}

func (p *PostgresService) RejectWalletChallenge(ctx context.Context, challengeID string) error {
	res, err := p.db.ExecContext(ctx, `UPDATE ap_wallet_challenge SET status = 'rejected' WHERE challenge_id = $1 AND status = 'consuming'`, challengeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrWalletChallengeInvalid
	}
	return nil
}

func (p *PostgresService) CreateIntent(ctx context.Context, intent *PaymentIntent) error {
	if intent == nil || intent.IntentID == "" {
		return errors.New("invalid payment intent")
	}
	if intent.ConfigVersionID == "" {
		intent.ConfigVersionID = "ver_default"
	}

	query := `
		INSERT INTO ap_payment_intent (
			intent_id, tenant_id, project_id, agent_id, route_id,
			idempotency_key, request_id, payment_method, amount_base_units,
			asset, status, config_version_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''), $5,
			NULLIF($6, ''), $7, $8, $9,
			$10, $11, $12, $13, $14
		)
		ON CONFLICT (intent_id) DO UPDATE SET
			agent_id = COALESCE(EXCLUDED.agent_id, ap_payment_intent.agent_id),
			idempotency_key = COALESCE(EXCLUDED.idempotency_key, ap_payment_intent.idempotency_key),
			request_id = CASE WHEN EXCLUDED.request_id <> '' THEN EXCLUDED.request_id ELSE ap_payment_intent.request_id END,
			status = EXCLUDED.status,
			updated_at = EXCLUDED.updated_at
	`
	now := time.Now()
	if intent.CreatedAt.IsZero() {
		intent.CreatedAt = now
	}
	intent.UpdatedAt = now

	_, err := p.db.ExecContext(ctx, query,
		intent.IntentID,
		intent.TenantID,
		intent.ProjectID,
		intent.AgentID,
		intent.RouteID,
		intent.IdempotencyKey,
		intent.RequestID,
		intent.PaymentMethod,
		intent.AmountBaseUnits,
		intent.Asset,
		intent.Status,
		intent.ConfigVersionID,
		intent.CreatedAt,
		intent.UpdatedAt,
	)
	return err
}

func (p *PostgresService) GetIntent(ctx context.Context, intentID string) (*PaymentIntent, error) {
	query := `
		SELECT
			intent_id, tenant_id, project_id, COALESCE(agent_id, ''), route_id,
			COALESCE(idempotency_key, ''), request_id, payment_method,
			amount_base_units, asset, status, config_version_id,
			created_at, updated_at
		FROM ap_payment_intent
		WHERE intent_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, intentID)
	var i PaymentIntent
	err := row.Scan(
		&i.IntentID, &i.TenantID, &i.ProjectID, &i.AgentID, &i.RouteID,
		&i.IdempotencyKey, &i.RequestID, &i.PaymentMethod,
		&i.AmountBaseUnits, &i.Asset, &i.Status, &i.ConfigVersionID,
		&i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIntentNotFound
		}
		return nil, err
	}
	return &i, nil
}

func (p *PostgresService) UpdateIntentStatus(ctx context.Context, intentID string, status string) error {
	query := `
		UPDATE ap_payment_intent
		SET status = $1, updated_at = CURRENT_TIMESTAMP
		WHERE intent_id = $2
	`
	res, err := p.db.ExecContext(ctx, query, status, intentID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrIntentNotFound
	}
	return nil
}

func (p *PostgresService) RecordSettlement(ctx context.Context, s *SettlementRecord) error {
	if s == nil || s.SettlementID == "" || s.IntentID == "" {
		return errors.New("invalid settlement record")
	}
	if s.Nonce == "" {
		s.Nonce = fmt.Sprintf("nonce_%s", s.SettlementID)
	}

	query := `
		INSERT INTO ap_settlement_record (
			settlement_id, intent_id, network_id, asset_address,
			payer_address, payee_address, amount_base_units, nonce,
			tx_hash, block_number, status, error_message,
			facilitator_settlement_id, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			NULLIF($9, ''), $10, $11, NULLIF($12, ''),
			NULLIF($13, ''), $14, $15
		)
		ON CONFLICT (settlement_id) DO UPDATE SET
			status = EXCLUDED.status,
			tx_hash = COALESCE(EXCLUDED.tx_hash, ap_settlement_record.tx_hash),
			block_number = COALESCE(EXCLUDED.block_number, ap_settlement_record.block_number),
			error_message = COALESCE(EXCLUDED.error_message, ap_settlement_record.error_message),
			facilitator_settlement_id = COALESCE(EXCLUDED.facilitator_settlement_id, ap_settlement_record.facilitator_settlement_id),
			updated_at = EXCLUDED.updated_at
	`
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := p.db.ExecContext(ctx, query,
		s.SettlementID,
		s.IntentID,
		s.NetworkID,
		s.AssetAddress,
		s.PayerAddress,
		s.PayeeAddress,
		s.AmountBaseUnits,
		s.Nonce,
		s.TxHash,
		s.BlockNumber,
		s.Status,
		s.ErrorMessage,
		s.FacilitatorSettlementID,
		s.CreatedAt,
		s.UpdatedAt,
	)
	return err
}

func (p *PostgresService) GetSettlement(ctx context.Context, settlementID string) (*SettlementRecord, error) {
	query := `
		SELECT
			settlement_id, intent_id, network_id, asset_address,
			payer_address, payee_address, amount_base_units, nonce,
			COALESCE(tx_hash, ''), block_number, status, COALESCE(error_message, ''),
			COALESCE(facilitator_settlement_id, ''), created_at, updated_at
		FROM ap_settlement_record
		WHERE settlement_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, settlementID)
	var s SettlementRecord
	err := row.Scan(
		&s.SettlementID, &s.IntentID, &s.NetworkID, &s.AssetAddress,
		&s.PayerAddress, &s.PayeeAddress, &s.AmountBaseUnits, &s.Nonce,
		&s.TxHash, &s.BlockNumber, &s.Status, &s.ErrorMessage,
		&s.FacilitatorSettlementID, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSettlementNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (p *PostgresService) GetSettlementByIntent(ctx context.Context, intentID string) (*SettlementRecord, error) {
	query := `
		SELECT
			settlement_id, intent_id, network_id, asset_address,
			payer_address, payee_address, amount_base_units, nonce,
			COALESCE(tx_hash, ''), block_number, status, COALESCE(error_message, ''),
			COALESCE(facilitator_settlement_id, ''), created_at, updated_at
		FROM ap_settlement_record
		WHERE intent_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, intentID)
	var s SettlementRecord
	err := row.Scan(
		&s.SettlementID, &s.IntentID, &s.NetworkID, &s.AssetAddress,
		&s.PayerAddress, &s.PayeeAddress, &s.AmountBaseUnits, &s.Nonce,
		&s.TxHash, &s.BlockNumber, &s.Status, &s.ErrorMessage,
		&s.FacilitatorSettlementID, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSettlementNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (p *PostgresService) UpdateSettlementStatus(ctx context.Context, settlementID string, status string, txHash string, blockNumber *int64, errMsg string) error {
	query := `
		UPDATE ap_settlement_record
		SET status = $1,
		    tx_hash = CASE WHEN $2 <> '' THEN $2 ELSE tx_hash END,
		    block_number = CASE WHEN $3::BIGINT IS NOT NULL THEN $3::BIGINT ELSE block_number END,
		    error_message = CASE WHEN $4 <> '' THEN $4 ELSE error_message END,
		    updated_at = CURRENT_TIMESTAMP
		WHERE settlement_id = $5
	`
	res, err := p.db.ExecContext(ctx, query, status, txHash, blockNumber, errMsg, settlementID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrSettlementNotFound
	}
	return nil
}

func (p *PostgresService) UpdateSettlementFacilitatorID(ctx context.Context, settlementID string, facilitatorSettlementID string) error {
	query := `
		UPDATE ap_settlement_record
		SET facilitator_settlement_id = NULLIF($1, ''),
		    updated_at = CURRENT_TIMESTAMP
		WHERE settlement_id = $2
	`
	res, err := p.db.ExecContext(ctx, query, facilitatorSettlementID, settlementID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrSettlementNotFound
	}
	return nil
}

func (p *PostgresService) ListNonTerminalSettlements(ctx context.Context) ([]*SettlementRecord, error) {
	query := `
		SELECT
			s.settlement_id, s.intent_id, COALESCE(i.payment_method, 'onchain'),
			s.network_id, s.asset_address, s.payer_address, s.payee_address,
			s.amount_base_units, s.nonce, COALESCE(s.tx_hash, ''), s.block_number,
			s.status, COALESCE(s.error_message, ''), COALESCE(s.facilitator_settlement_id, ''),
			s.created_at, s.updated_at
		FROM ap_settlement_record s
		LEFT JOIN ap_payment_intent i ON i.intent_id = s.intent_id
		WHERE COALESCE(i.payment_method, 'onchain') = 'onchain'
		  AND s.status IN ('submitted', 'pending', 'unknown')
		ORDER BY s.created_at ASC
		LIMIT 200
	`
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SettlementRecord
	for rows.Next() {
		var s SettlementRecord
		if err := rows.Scan(
			&s.SettlementID, &s.IntentID, &s.PaymentMethod,
			&s.NetworkID, &s.AssetAddress, &s.PayerAddress, &s.PayeeAddress,
			&s.AmountBaseUnits, &s.Nonce, &s.TxHash, &s.BlockNumber,
			&s.Status, &s.ErrorMessage, &s.FacilitatorSettlementID,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

func (p *PostgresService) RecordFulfillment(ctx context.Context, f *FulfillmentRecord) error {
	if f == nil || f.FulfillmentID == "" || f.IntentID == "" {
		return errors.New("invalid fulfillment record")
	}

	query := `
		INSERT INTO ap_fulfillment_record (
			fulfillment_id, intent_id, upstream_url, upstream_status,
			latency_ms, response_body_hash, status, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, NULLIF($6, ''), $7, $8, $9
		)
		ON CONFLICT (fulfillment_id) DO UPDATE SET
			status = EXCLUDED.status,
			upstream_status = COALESCE(EXCLUDED.upstream_status, ap_fulfillment_record.upstream_status),
			latency_ms = COALESCE(EXCLUDED.latency_ms, ap_fulfillment_record.latency_ms),
			response_body_hash = COALESCE(EXCLUDED.response_body_hash, ap_fulfillment_record.response_body_hash),
			updated_at = EXCLUDED.updated_at
	`
	now := time.Now()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.UpdatedAt = now

	_, err := p.db.ExecContext(ctx, query,
		f.FulfillmentID,
		f.IntentID,
		f.UpstreamURL,
		f.UpstreamStatus,
		f.LatencyMs,
		f.ResponseBodyHash,
		f.Status,
		f.CreatedAt,
		f.UpdatedAt,
	)
	return err
}

func (p *PostgresService) GetFulfillment(ctx context.Context, fulfillmentID string) (*FulfillmentRecord, error) {
	query := `
		SELECT
			fulfillment_id, intent_id, upstream_url, COALESCE(upstream_status, 0),
			COALESCE(latency_ms, 0), COALESCE(response_body_hash, ''), status,
			created_at, updated_at
		FROM ap_fulfillment_record
		WHERE fulfillment_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, fulfillmentID)
	var f FulfillmentRecord
	err := row.Scan(
		&f.FulfillmentID, &f.IntentID, &f.UpstreamURL, &f.UpstreamStatus,
		&f.LatencyMs, &f.ResponseBodyHash, &f.Status,
		&f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFulfillmentNotFound
		}
		return nil, err
	}
	return &f, nil
}

func (p *PostgresService) GetFulfillmentByIntent(ctx context.Context, intentID string) (*FulfillmentRecord, error) {
	query := `
		SELECT
			fulfillment_id, intent_id, upstream_url, COALESCE(upstream_status, 0),
			COALESCE(latency_ms, 0), COALESCE(response_body_hash, ''), status,
			created_at, updated_at
		FROM ap_fulfillment_record
		WHERE intent_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, intentID)
	var f FulfillmentRecord
	err := row.Scan(
		&f.FulfillmentID, &f.IntentID, &f.UpstreamURL, &f.UpstreamStatus,
		&f.LatencyMs, &f.ResponseBodyHash, &f.Status,
		&f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrFulfillmentNotFound
		}
		return nil, err
	}
	return &f, nil
}

func (p *PostgresService) UpdateFulfillment(ctx context.Context, fulfillmentID string, status string, upstreamStatus int, latencyMs int64, bodyHash string) error {
	query := `
		UPDATE ap_fulfillment_record
		SET status = $1,
		    upstream_status = CASE WHEN $2 > 0 THEN $2 ELSE upstream_status END,
		    latency_ms = CASE WHEN $3 > 0 THEN $3 ELSE latency_ms END,
		    response_body_hash = CASE WHEN $4 <> '' THEN $4 ELSE response_body_hash END,
		    updated_at = CURRENT_TIMESTAMP
		WHERE fulfillment_id = $5
	`
	res, err := p.db.ExecContext(ctx, query, status, upstreamStatus, latencyMs, bodyHash, fulfillmentID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrFulfillmentNotFound
	}
	return nil
}

func (p *PostgresService) LinkWalletAssociation(ctx context.Context, intentID string, hold *WalletHoldAssociation, ledger *LedgerAssociation) error {
	// Holds and Ledgers are written directly to ap_hold and ap_ledger_entry in wallet.Service.
	// Postgres joins them automatically on payment_intent_id / ref_id.
	return nil
}

func (p *PostgresService) ExpireStaleHolds(ctx context.Context, before time.Time) (int64, error) {
	res, err := p.db.ExecContext(ctx, `
		UPDATE ap_settlement_record s
		SET status = 'released', updated_at = CURRENT_TIMESTAMP
		FROM ap_hold h
		WHERE h.payment_intent_id = s.intent_id
		  AND h.status = 'expired'
		  AND s.status = 'held'
	`)
	if err != nil {
		return 0, err
	}
	count, _ := res.RowsAffected()
	return count, nil
}

func (p *PostgresService) GetPaymentAudit(ctx context.Context, tenantID, intentID string) (*PaymentAuditRecord, error) {
	query := `
		SELECT
			i.intent_id, i.tenant_id, i.project_id, COALESCE(i.agent_id, ''),
			i.route_id, i.request_id, COALESCE(i.idempotency_key, ''),
			i.payment_method, i.amount_base_units, i.asset, i.status,
			i.config_version_id, i.created_at, i.updated_at,
			s.settlement_id, COALESCE(s.network_id, ''), COALESCE(s.asset_address, ''),
			COALESCE(s.payer_address, ''), COALESCE(s.payee_address, ''),
			COALESCE(s.amount_base_units, 0), COALESCE(s.nonce, ''),
			COALESCE(s.tx_hash, ''), s.block_number, COALESCE(s.status, 'not_started'),
			COALESCE(s.error_message, ''), s.created_at, s.updated_at,
			f.fulfillment_id, COALESCE(f.upstream_url, ''), COALESCE(f.upstream_status, 0),
			COALESCE(f.latency_ms, 0), COALESCE(f.response_body_hash, ''),
			COALESCE(f.status, 'not_started'), f.created_at, f.updated_at,
			h.hold_id, COALESCE(h.wallet_id, ''), COALESCE(h.amount, 0),
			COALESCE(h.status, ''), h.expires_at,
			l.entry_id, COALESCE(l.wallet_id, ''), COALESCE(l.type, ''),
			COALESCE(l.amount, 0), l.created_at
		FROM ap_payment_intent i
		LEFT JOIN ap_settlement_record s ON s.intent_id = i.intent_id
		LEFT JOIN ap_fulfillment_record f ON f.intent_id = i.intent_id
		LEFT JOIN ap_hold h ON h.payment_intent_id = i.intent_id
		LEFT JOIN ap_ledger_entry l ON ((l.ref_type = 'PaymentIntent' AND l.ref_id = i.intent_id) OR (l.ref_type = 'Hold' AND l.ref_id = h.hold_id))
		WHERE i.intent_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, intentID)
	rec, err := scanPaymentAudit(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIntentNotFound
		}
		return nil, err
	}
	if tenantID != "" && rec.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return rec, nil
}

func (p *PostgresService) GetPaymentAuditByRequestID(ctx context.Context, tenantID, requestID string) (*PaymentAuditRecord, error) {
	query := `
		SELECT
			i.intent_id, i.tenant_id, i.project_id, COALESCE(i.agent_id, ''),
			i.route_id, i.request_id, COALESCE(i.idempotency_key, ''),
			i.payment_method, i.amount_base_units, i.asset, i.status,
			i.config_version_id, i.created_at, i.updated_at,
			s.settlement_id, COALESCE(s.network_id, ''), COALESCE(s.asset_address, ''),
			COALESCE(s.payer_address, ''), COALESCE(s.payee_address, ''),
			COALESCE(s.amount_base_units, 0), COALESCE(s.nonce, ''),
			COALESCE(s.tx_hash, ''), s.block_number, COALESCE(s.status, 'not_started'),
			COALESCE(s.error_message, ''), s.created_at, s.updated_at,
			f.fulfillment_id, COALESCE(f.upstream_url, ''), COALESCE(f.upstream_status, 0),
			COALESCE(f.latency_ms, 0), COALESCE(f.response_body_hash, ''),
			COALESCE(f.status, 'not_started'), f.created_at, f.updated_at,
			h.hold_id, COALESCE(h.wallet_id, ''), COALESCE(h.amount, 0),
			COALESCE(h.status, ''), h.expires_at,
			l.entry_id, COALESCE(l.wallet_id, ''), COALESCE(l.type, ''),
			COALESCE(l.amount, 0), l.created_at
		FROM ap_payment_intent i
		LEFT JOIN ap_settlement_record s ON s.intent_id = i.intent_id
		LEFT JOIN ap_fulfillment_record f ON f.intent_id = i.intent_id
		LEFT JOIN ap_hold h ON h.payment_intent_id = i.intent_id
		LEFT JOIN ap_ledger_entry l ON ((l.ref_type = 'PaymentIntent' AND l.ref_id = i.intent_id) OR (l.ref_type = 'Hold' AND l.ref_id = h.hold_id))
		WHERE i.request_id = $1
	`
	row := p.db.QueryRowContext(ctx, query, requestID)
	rec, err := scanPaymentAudit(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIntentNotFound
		}
		return nil, err
	}
	if tenantID != "" && rec.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	return rec, nil
}

func (p *PostgresService) ListPaymentAudits(ctx context.Context, filter PaymentAuditFilter) ([]*PaymentAuditRecord, int64, error) {
	var whereClauses []string
	var args []interface{}
	argIdx := 1

	if filter.TenantID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID)
		argIdx++
	}
	if filter.ProjectID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.project_id = $%d", argIdx))
		args = append(args, filter.ProjectID)
		argIdx++
	}
	if filter.AgentID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.agent_id = $%d", argIdx))
		args = append(args, filter.AgentID)
		argIdx++
	}
	if filter.RouteID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.route_id = $%d", argIdx))
		args = append(args, filter.RouteID)
		argIdx++
	}
	if filter.PaymentMethod != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.payment_method = $%d", argIdx))
		args = append(args, filter.PaymentMethod)
		argIdx++
	}
	if filter.IntentStatus != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("i.status = $%d", argIdx))
		args = append(args, filter.IntentStatus)
		argIdx++
	}
	if filter.StartTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("i.created_at >= $%d", argIdx))
		args = append(args, *filter.StartTime)
		argIdx++
	}
	if filter.EndTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("i.created_at <= $%d", argIdx))
		args = append(args, *filter.EndTime)
		argIdx++
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM ap_payment_intent i %s", whereSQL)
	var total int64
	if err := p.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	listQuery := fmt.Sprintf(`
		SELECT
			i.intent_id, i.tenant_id, i.project_id, COALESCE(i.agent_id, ''),
			i.route_id, i.request_id, COALESCE(i.idempotency_key, ''),
			i.payment_method, i.amount_base_units, i.asset, i.status,
			i.config_version_id, i.created_at, i.updated_at,
			s.settlement_id, COALESCE(s.network_id, ''), COALESCE(s.asset_address, ''),
			COALESCE(s.payer_address, ''), COALESCE(s.payee_address, ''),
			COALESCE(s.amount_base_units, 0), COALESCE(s.nonce, ''),
			COALESCE(s.tx_hash, ''), s.block_number, COALESCE(s.status, 'not_started'),
			COALESCE(s.error_message, ''), s.created_at, s.updated_at,
			f.fulfillment_id, COALESCE(f.upstream_url, ''), COALESCE(f.upstream_status, 0),
			COALESCE(f.latency_ms, 0), COALESCE(f.response_body_hash, ''),
			COALESCE(f.status, 'not_started'), f.created_at, f.updated_at,
			h.hold_id, COALESCE(h.wallet_id, ''), COALESCE(h.amount, 0),
			COALESCE(h.status, ''), h.expires_at,
			l.entry_id, COALESCE(l.wallet_id, ''), COALESCE(l.type, ''),
			COALESCE(l.amount, 0), l.created_at
		FROM ap_payment_intent i
		LEFT JOIN ap_settlement_record s ON s.intent_id = i.intent_id
		LEFT JOIN ap_fulfillment_record f ON f.intent_id = i.intent_id
		LEFT JOIN ap_hold h ON h.payment_intent_id = i.intent_id
		LEFT JOIN ap_ledger_entry l ON ((l.ref_type = 'PaymentIntent' AND l.ref_id = i.intent_id) OR (l.ref_type = 'Hold' AND l.ref_id = h.hold_id))
		%s
		ORDER BY i.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, argIdx, argIdx+1)

	args = append(args, limit, offset)
	rows, err := p.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var records []*PaymentAuditRecord
	for rows.Next() {
		rec, err := scanPaymentAudit(rows)
		if err != nil {
			return nil, 0, err
		}
		if filter.DisplayStatus != "" && rec.DisplayStatus != filter.DisplayStatus {
			continue
		}
		records = append(records, rec)
	}

	return records, total, rows.Err()
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanPaymentAudit(row scannable) (*PaymentAuditRecord, error) {
	var (
		i     PaymentIntent
		stlID sql.NullString
		s     SettlementRecord
		fulID sql.NullString
		f     FulfillmentRecord
		hldID sql.NullString
		h     WalletHoldAssociation
		hExp  sql.NullTime
		ledID sql.NullString
		l     LedgerAssociation
		lTime sql.NullTime
		sTime sql.NullTime
		sUpd  sql.NullTime
		fTime sql.NullTime
		fUpd  sql.NullTime
	)

	err := row.Scan(
		&i.IntentID, &i.TenantID, &i.ProjectID, &i.AgentID,
		&i.RouteID, &i.RequestID, &i.IdempotencyKey,
		&i.PaymentMethod, &i.AmountBaseUnits, &i.Asset, &i.Status,
		&i.ConfigVersionID, &i.CreatedAt, &i.UpdatedAt,
		&stlID, &s.NetworkID, &s.AssetAddress,
		&s.PayerAddress, &s.PayeeAddress,
		&s.AmountBaseUnits, &s.Nonce,
		&s.TxHash, &s.BlockNumber, &s.Status,
		&s.ErrorMessage, &sTime, &sUpd,
		&fulID, &f.UpstreamURL, &f.UpstreamStatus,
		&f.LatencyMs, &f.ResponseBodyHash,
		&f.Status, &fTime, &fUpd,
		&hldID, &h.WalletID, &h.Amount,
		&h.Status, &hExp,
		&ledID, &l.WalletID, &l.Type,
		&l.Amount, &lTime,
	)
	if err != nil {
		return nil, err
	}

	var settlementPtr *SettlementRecord
	settlementStatus := SettlementStatusNotStarted
	if stlID.Valid && stlID.String != "" {
		s.SettlementID = stlID.String
		s.IntentID = i.IntentID
		s.PaymentMethod = i.PaymentMethod
		if sTime.Valid {
			s.CreatedAt = sTime.Time
		}
		if sUpd.Valid {
			s.UpdatedAt = sUpd.Time
		}
		settlementPtr = &s
		settlementStatus = s.Status
	}

	var fulfillmentPtr *FulfillmentRecord
	fulfillmentStatus := FulfillmentStatusNotStarted
	if fulID.Valid && fulID.String != "" {
		f.FulfillmentID = fulID.String
		f.IntentID = i.IntentID
		if fTime.Valid {
			f.CreatedAt = fTime.Time
		}
		if fUpd.Valid {
			f.UpdatedAt = fUpd.Time
		}
		fulfillmentPtr = &f
		fulfillmentStatus = f.Status
	}

	var holdPtr *WalletHoldAssociation
	if hldID.Valid && hldID.String != "" {
		h.HoldID = hldID.String
		if hExp.Valid {
			h.ExpiresAt = hExp.Time
		}
		holdPtr = &h
	}

	var ledgerPtr *LedgerAssociation
	if ledID.Valid && ledID.String != "" {
		l.EntryID = ledID.String
		if lTime.Valid {
			l.CreatedAt = lTime.Time
		}
		ledgerPtr = &l
	}

	displayStatus, displayNote, isRecovery := DeriveCompositeDisplayStatus(i.Status, settlementStatus, fulfillmentStatus)

	return &PaymentAuditRecord{
		IntentID:           i.IntentID,
		TenantID:           i.TenantID,
		ProjectID:          i.ProjectID,
		AgentID:            i.AgentID,
		RouteID:            i.RouteID,
		RequestID:          i.RequestID,
		IdempotencyKey:     i.IdempotencyKey,
		PaymentMethod:      i.PaymentMethod,
		AmountBaseUnits:    i.AmountBaseUnits,
		Asset:              i.Asset,
		DisplayStatus:      displayStatus,
		DisplayNote:        displayNote,
		IsRecoveryRequired: isRecovery,
		IntentStatus:       i.Status,
		SettlementStatus:   settlementStatus,
		FulfillmentStatus:  fulfillmentStatus,
		Intent:             &i,
		Settlement:         settlementPtr,
		Fulfillment:        fulfillmentPtr,
		Hold:               holdPtr,
		Ledger:             ledgerPtr,
		CreatedAt:          i.CreatedAt,
		UpdatedAt:          i.UpdatedAt,
	}, nil
}
