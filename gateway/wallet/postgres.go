package wallet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"github.com/open-agentpay/agent-core-sdk/gateway/x402"
)

// PostgresService implements the Service interface against a PostgreSQL 15+ database.
type PostgresService struct {
	db             *sql.DB
	defaultHoldTTL time.Duration
}

// NewPostgresService creates an initialized PostgresService.
func NewPostgresService(db *sql.DB, defaultHoldTTL time.Duration) *PostgresService {
	if defaultHoldTTL <= 0 {
		defaultHoldTTL = 120 * time.Second
	}
	return &PostgresService{
		db:             db,
		defaultHoldTTL: defaultHoldTTL,
	}
}

// GetWalletByAPIKey resolves an API key token to the tenant's primary wallet account.
func (p *PostgresService) GetWalletByAPIKey(ctx context.Context, apiKey string) (*x402.WalletAccount, error) {
	keyHash := HashAPIKey(apiKey)

	query := `
		SELECT ak.key_id, ak.tenant_id, ak.status, ak.expires_at,
		       w.wallet_id, w.status, w.available_cache, w.held_cache,
		       ak.project_id, ak.agent_id
		FROM ap_api_key ak
		JOIN ap_wallet w ON w.tenant_id = ak.tenant_id
		WHERE (ak.key_hash = $1 OR ak.key_id = $2) AND ak.status = 'active'
		LIMIT 1;
	`

	var (
		apiKeyID         string
		tenantID         string
		keyStatus        string
		keyExpiresAt     sql.NullTime
		walletID         string
		walletStatus     string
		availableBalance int64
		heldBalance      int64
		projectID        sql.NullString
		agentID          sql.NullString
	)

	err := p.db.QueryRowContext(ctx, query, keyHash, apiKey).Scan(
		&apiKeyID,
		&tenantID,
		&keyStatus,
		&keyExpiresAt,
		&walletID,
		&walletStatus,
		&availableBalance,
		&heldBalance,
		&projectID,
		&agentID,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAPIKeyInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lookup API key: %w", err)
	}

	if keyExpiresAt.Valid && keyExpiresAt.Time.Before(time.Now()) {
		return nil, ErrAPIKeyInvalid
	}

	var pID, aID string
	if projectID.Valid {
		pID = projectID.String
	}
	if agentID.Valid {
		aID = agentID.String
	}

	return &x402.WalletAccount{
		WalletID:         walletID,
		TenantID:         tenantID,
		APIKeyID:         apiKeyID,
		ProjectID:        pID,
		AgentID:          aID,
		Status:           walletStatus,
		AvailableBalance: availableBalance,
		HeldBalance:      heldBalance,
	}, nil
}

// GetWallet retrieves wallet details by walletID.
func (p *PostgresService) GetWallet(ctx context.Context, walletID string) (*Wallet, error) {
	query := `
		SELECT wallet_id, tenant_id, asset, status, version, available_cache, held_cache, created_at, updated_at
		FROM ap_wallet
		WHERE wallet_id = $1;
	`
	w := &Wallet{}
	err := p.db.QueryRowContext(ctx, query, walletID).Scan(
		&w.WalletID,
		&w.TenantID,
		&w.Asset,
		&w.Status,
		&w.Version,
		&w.AvailableCache,
		&w.HeldCache,
		&w.CreatedAt,
		&w.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	return w, nil
}

// GetWalletByTenant retrieves wallet details by tenantID.
func (p *PostgresService) GetWalletByTenant(ctx context.Context, tenantID string) (*Wallet, error) {
	query := `
		SELECT wallet_id, tenant_id, asset, status, version, available_cache, held_cache, created_at, updated_at
		FROM ap_wallet
		WHERE tenant_id = $1;
	`
	w := &Wallet{}
	err := p.db.QueryRowContext(ctx, query, tenantID).Scan(
		&w.WalletID,
		&w.TenantID,
		&w.Asset,
		&w.Status,
		&w.Version,
		&w.AvailableCache,
		&w.HeldCache,
		&w.CreatedAt,
		&w.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant wallet: %w", err)
	}
	return w, nil
}

// HoldFunds atomically locks the wallet row, checks available balance, and inserts an ap_hold record.
func (p *PostgresService) HoldFunds(ctx context.Context, walletID string, amount int64, intentID string) (string, error) {
	if amount <= 0 {
		return "", fmt.Errorf("hold amount must be positive, got %d", amount)
	}

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		status         string
		version        int64
		availableCache int64
		heldCache      int64
	)

	lockQuery := `
		SELECT status, version, available_cache, held_cache
		FROM ap_wallet
		WHERE wallet_id = $1
		FOR UPDATE;
	`
	err = tx.QueryRowContext(ctx, lockQuery, walletID).Scan(&status, &version, &availableCache, &heldCache)
	if err == sql.ErrNoRows {
		return "", ErrWalletNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to lock wallet row: %w", err)
	}

	if status == string(StatusFrozen) || status == string(StatusFrozenArrears) || status == string(StatusClosed) {
		return "", ErrWalletFrozen
	}

	if availableCache < amount {
		return "", ErrInsufficientBalance
	}

	// Update wallet caches
	updateWalletQuery := `
		UPDATE ap_wallet
		SET available_cache = available_cache - $1,
		    held_cache = held_cache + $1,
		    version = version + 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE wallet_id = $2;
	`
	if _, err := tx.ExecContext(ctx, updateWalletQuery, amount, walletID); err != nil {
		return "", fmt.Errorf("failed to update wallet cache: %w", err)
	}

	holdID := fmt.Sprintf("hld_%s_%d", intentID, time.Now().UnixNano())
	expiresAt := time.Now().Add(p.defaultHoldTTL)

	insertHoldQuery := `
		INSERT INTO ap_hold (hold_id, wallet_id, payment_intent_id, amount, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 'held', $5, CURRENT_TIMESTAMP);
	`
	if _, err := tx.ExecContext(ctx, insertHoldQuery, holdID, walletID, intentID, amount, expiresAt); err != nil {
		return "", fmt.Errorf("failed to insert hold: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit hold: %w", err)
	}

	return holdID, nil
}

// CaptureFunds confirms hold deduction and writes append-only ledger entry.
func (p *PostgresService) CaptureFunds(ctx context.Context, holdID string) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		walletID string
		amount   int64
		status   string
	)

	holdQuery := `
		SELECT wallet_id, amount, status
		FROM ap_hold
		WHERE hold_id = $1
		FOR UPDATE;
	`
	err = tx.QueryRowContext(ctx, holdQuery, holdID).Scan(&walletID, &amount, &status)
	if err == sql.ErrNoRows {
		return ErrHoldNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to query hold: %w", err)
	}

	// Idempotent completion check
	if status == string(HoldStatusCaptured) {
		return nil
	}

	if status != string(HoldStatusHeld) {
		return fmt.Errorf("cannot capture hold in state: %s", status)
	}

	var tenantID string
	walletQuery := `
		SELECT tenant_id
		FROM ap_wallet
		WHERE wallet_id = $1
		FOR UPDATE;
	`
	if err := tx.QueryRowContext(ctx, walletQuery, walletID).Scan(&tenantID); err != nil {
		return fmt.Errorf("failed to lock wallet: %w", err)
	}

	// Update wallet held cache
	updateWallet := `
		UPDATE ap_wallet
		SET held_cache = held_cache - $1,
		    version = version + 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE wallet_id = $2;
	`
	if _, err := tx.ExecContext(ctx, updateWallet, amount, walletID); err != nil {
		return fmt.Errorf("failed to deduct held cache: %w", err)
	}

	// Mark hold as captured
	updateHold := `
		UPDATE ap_hold
		SET status = 'captured'
		WHERE hold_id = $1;
	`
	if _, err := tx.ExecContext(ctx, updateHold, holdID); err != nil {
		return fmt.Errorf("failed to mark hold captured: %w", err)
	}

	// Append immutable financial ledger entry
	entryID := fmt.Sprintf("ent_%d", time.Now().UnixNano())
	idemKey := "cap_" + holdID
	insertLedger := `
		INSERT INTO ap_ledger_entry (
			entry_id, wallet_id, tenant_id, type, amount, idempotency_key, ref_type, ref_id, created_at
		) VALUES (
			$1, $2, $3, 'capture', -CAST($4 AS BIGINT), $5, 'Hold', $6, CURRENT_TIMESTAMP
		)
		ON CONFLICT (wallet_id, idempotency_key) DO NOTHING;
	`
	if _, err := tx.ExecContext(ctx, insertLedger, entryID, walletID, tenantID, amount, idemKey, holdID); err != nil {
		return fmt.Errorf("failed to write append-only ledger entry: %w", err)
	}

	return tx.Commit()
}

// ReleaseFunds cancels the hold reservation and restores available cache.
func (p *PostgresService) ReleaseFunds(ctx context.Context, holdID string) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		walletID string
		amount   int64
		status   string
	)

	holdQuery := `
		SELECT wallet_id, amount, status
		FROM ap_hold
		WHERE hold_id = $1
		FOR UPDATE;
	`
	err = tx.QueryRowContext(ctx, holdQuery, holdID).Scan(&walletID, &amount, &status)
	if err == sql.ErrNoRows {
		return ErrHoldNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to query hold: %w", err)
	}

	// Idempotent release check
	if status == string(HoldStatusReleased) {
		return nil
	}

	if status != string(HoldStatusHeld) {
		return fmt.Errorf("cannot release hold in state: %s", status)
	}

	walletQuery := `
		UPDATE ap_wallet
		SET held_cache = held_cache - $1,
		    available_cache = available_cache + $1,
		    version = version + 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE wallet_id = $2;
	`
	if _, err := tx.ExecContext(ctx, walletQuery, amount, walletID); err != nil {
		return fmt.Errorf("failed to restore wallet balance: %w", err)
	}

	updateHold := `
		UPDATE ap_hold
		SET status = 'released'
		WHERE hold_id = $1;
	`
	if _, err := tx.ExecContext(ctx, updateHold, holdID); err != nil {
		return fmt.Errorf("failed to mark hold released: %w", err)
	}

	return tx.Commit()
}

// CreditTopUp increases available balance and commits topup order & ledger entry.
func (p *PostgresService) CreditTopUp(ctx context.Context, order *TopUpOrder) error {
	if order.Amount <= 0 {
		return fmt.Errorf("topup amount must be positive, got %d", order.Amount)
	}

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		currentStatus string
		available     int64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT status, available_cache
		FROM ap_wallet
		WHERE wallet_id = $1
		FOR UPDATE;
	`, order.WalletID).Scan(&currentStatus, &available)
	if err == sql.ErrNoRows {
		return ErrWalletNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to lock wallet: %w", err)
	}

	// Insert topup order
	insertTopUp := `
		INSERT INTO ap_topup_order (
			topup_id, wallet_id, tenant_id, channel, amount, asset, status, external_ref, operator_id, reason, created_at, confirmed_at
		) VALUES (
			$1, $2, $3, $4, $5, 'CNY', 'confirmed', $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		);
	`
	if _, err := tx.ExecContext(ctx, insertTopUp, order.TopUpID, order.WalletID, order.TenantID, string(order.Channel), order.Amount, order.ExternalRef, order.OperatorID, order.Reason); err != nil {
		return fmt.Errorf("failed to insert topup order: %w", err)
	}

	// Append immutable ledger credit
	entryID := fmt.Sprintf("ent_%d", time.Now().UnixNano())
	idemKey := "top_" + order.TopUpID
	insertLedger := `
		INSERT INTO ap_ledger_entry (
			entry_id, wallet_id, tenant_id, type, amount, idempotency_key, ref_type, ref_id, operator_id, reason, created_at
		) VALUES (
			$1, $2, $3, 'topup_credit', $4, $5, 'TopUpOrder', $6, $7, $8, CURRENT_TIMESTAMP
		)
		ON CONFLICT (wallet_id, idempotency_key) DO NOTHING;
	`
	if _, err := tx.ExecContext(ctx, insertLedger, entryID, order.WalletID, order.TenantID, order.Amount, idemKey, order.TopUpID, order.OperatorID, order.Reason); err != nil {
		return fmt.Errorf("failed to insert topup ledger entry: %w", err)
	}

	newStatus := currentStatus
	if currentStatus == string(StatusFrozenArrears) && (available+order.Amount) >= 0 {
		newStatus = string(StatusActive)
	}

	updateWallet := `
		UPDATE ap_wallet
		SET available_cache = available_cache + $1,
		    status = $2,
		    version = version + 1,
		    updated_at = CURRENT_TIMESTAMP
		WHERE wallet_id = $3;
	`
	if _, err := tx.ExecContext(ctx, updateWallet, order.Amount, newStatus, order.WalletID); err != nil {
		return fmt.Errorf("failed to update wallet balance: %w", err)
	}

	return tx.Commit()
}

// ReleaseExpiredHolds sweeps all expired active holds and refunds amounts to available cache.
func (p *PostgresService) ReleaseExpiredHolds(ctx context.Context, before time.Time) (int64, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		SELECT hold_id, wallet_id, amount
		FROM ap_hold
		WHERE status = 'held' AND expires_at <= $1
		FOR UPDATE;
	`
	rows, err := tx.QueryContext(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired holds: %w", err)
	}
	defer rows.Close()

	type ExpiredHold struct {
		HoldID   string
		WalletID string
		Amount   int64
	}
	var expiredList []ExpiredHold

	for rows.Next() {
		var eh ExpiredHold
		if err := rows.Scan(&eh.HoldID, &eh.WalletID, &eh.Amount); err != nil {
			return 0, fmt.Errorf("failed to scan expired hold: %w", err)
		}
		expiredList = append(expiredList, eh)
	}
	rows.Close()

	for _, eh := range expiredList {
		if _, err := tx.ExecContext(ctx, "UPDATE ap_hold SET status = 'expired' WHERE hold_id = $1", eh.HoldID); err != nil {
			return 0, fmt.Errorf("failed to update hold to expired: %w", err)
		}

		updateWallet := `
			UPDATE ap_wallet
			SET held_cache = held_cache - $1,
			    available_cache = available_cache + $1,
			    version = version + 1,
			    updated_at = CURRENT_TIMESTAMP
			WHERE wallet_id = $2;
		`
		if _, err := tx.ExecContext(ctx, updateWallet, eh.Amount, eh.WalletID); err != nil {
			return 0, fmt.Errorf("failed to refund expired hold: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit expired holds sweep: %w", err)
	}

	return int64(len(expiredList)), nil
}

// GetLedgerEntries retrieves all immutable financial ledger rows for a wallet.
func (p *PostgresService) GetLedgerEntries(ctx context.Context, walletID string) ([]*LedgerEntry, error) {
	query := `
		SELECT entry_id, wallet_id, tenant_id, type, amount, idempotency_key, ref_type, ref_id,
		       COALESCE(operator_id, ''), COALESCE(reason, ''), created_at
		FROM ap_ledger_entry
		WHERE wallet_id = $1
		ORDER BY created_at ASC;
	`
	rows, err := p.db.QueryContext(ctx, query, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to query ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*LedgerEntry
	for rows.Next() {
		e := &LedgerEntry{}
		if err := rows.Scan(
			&e.EntryID,
			&e.WalletID,
			&e.TenantID,
			&e.Type,
			&e.Amount,
			&e.IdempotencyKey,
			&e.RefType,
			&e.RefID,
			&e.OperatorID,
			&e.Reason,
			&e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ledger row: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetTopUpOrders retrieves all topup orders for a wallet.
func (p *PostgresService) GetTopUpOrders(ctx context.Context, walletID string) ([]*TopUpOrder, error) {
	query := `
		SELECT topup_id, wallet_id, tenant_id, channel, amount, asset, status,
		       COALESCE(external_ref, ''), COALESCE(operator_id, ''), COALESCE(reason, ''),
		       created_at, confirmed_at
		FROM ap_topup_order
		WHERE wallet_id = $1
		ORDER BY created_at DESC;
	`
	rows, err := p.db.QueryContext(ctx, query, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to query topup orders: %w", err)
	}
	defer rows.Close()

	var orders []*TopUpOrder
	for rows.Next() {
		o := &TopUpOrder{}
		var confirmedAt sql.NullTime
		if err := rows.Scan(
			&o.TopUpID,
			&o.WalletID,
			&o.TenantID,
			&o.Channel,
			&o.Amount,
			&o.Asset,
			&o.Status,
			&o.ExternalRef,
			&o.OperatorID,
			&o.Reason,
			&o.CreatedAt,
			&confirmedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan topup order row: %w", err)
		}
		if confirmedAt.Valid {
			o.ConfirmedAt = confirmedAt.Time
		}
		orders = append(orders, o)
	}
	return orders, nil
}

// ReconcileBalance computes double-entry balance check against immutable ledger and active holds.
func (p *PostgresService) ReconcileBalance(ctx context.Context, walletID string) (*ReconciliationReport, error) {
	var (
		available int64
		held      int64
	)
	err := p.db.QueryRowContext(ctx, "SELECT available_cache, held_cache FROM ap_wallet WHERE wallet_id = $1", walletID).Scan(&available, &held)
	if err == sql.ErrNoRows {
		return nil, ErrWalletNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query wallet: %w", err)
	}

	var sumLedger int64
	err = p.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(amount), 0) FROM ap_ledger_entry WHERE wallet_id = $1", walletID).Scan(&sumLedger)
	if err != nil {
		return nil, fmt.Errorf("failed to sum ledger entries: %w", err)
	}

	var sumActiveHolds int64
	err = p.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(amount), 0) FROM ap_hold WHERE wallet_id = $1 AND status = 'held'", walletID).Scan(&sumActiveHolds)
	if err != nil {
		return nil, fmt.Errorf("failed to sum active holds: %w", err)
	}

	totalInWallet := available + held
	isBalanced := (sumActiveHolds == held)
	discrepancy := totalInWallet - sumLedger

	return &ReconciliationReport{
		WalletID:         walletID,
		AvailableCache:   available,
		HeldCache:        held,
		TotalInWallet:    totalInWallet,
		SumLedgerEntries: sumLedger,
		SumActiveHolds:   sumActiveHolds,
		IsBalanced:       isBalanced,
		Discrepancy:      discrepancy,
	}, nil
}

// AdjustBalance increases or decreases available funds and registers ledger adjustment in PostgreSQL.
func (p *PostgresService) AdjustBalance(ctx context.Context, walletID string, amount int64, reason, idempotencyKey, operatorID string) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		tenantID       string
		status         string
		version        int64
		availableCache int64
	)
	query := `SELECT tenant_id, status, version, available_cache FROM ap_wallet WHERE wallet_id = $1 FOR UPDATE;`
	if err := tx.QueryRowContext(ctx, query, walletID).Scan(&tenantID, &status, &version, &availableCache); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrWalletNotFound
		}
		return fmt.Errorf("failed to lock wallet: %w", err)
	}

	newAvailable := availableCache + amount
	newStatus := status
	if status == string(StatusFrozenArrears) && newAvailable >= 0 {
		newStatus = string(StatusActive)
	} else if status == string(StatusActive) && newAvailable < 0 {
		newStatus = string(StatusFrozenArrears)
	}

	now := time.Now()
	updateQuery := `
		UPDATE ap_wallet
		SET available_cache = $1, status = $2, version = version + 1, updated_at = $3
		WHERE wallet_id = $4;
	`
	if _, err := tx.ExecContext(ctx, updateQuery, newAvailable, newStatus, now, walletID); err != nil {
		return fmt.Errorf("failed to update wallet: %w", err)
	}

	idemKey := idempotencyKey
	if idemKey == "" {
		idemKey = fmt.Sprintf("adj_%d", now.UnixNano())
	}
	entryID := fmt.Sprintf("ent_%d", now.UnixNano())
	ledgerQuery := `
		INSERT INTO ap_wallet_ledger (
			entry_id, wallet_id, tenant_id, type, amount, idempotency_key, ref_type, ref_id, operator_id, reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (wallet_id, idempotency_key) DO NOTHING;
	`
	if _, err := tx.ExecContext(ctx, ledgerQuery, entryID, walletID, tenantID, string(LedgerTypeAdjustment), amount, idemKey, "Adjustment", idemKey, operatorID, reason, now); err != nil {
		return fmt.Errorf("failed to write ledger entry: %w", err)
	}

	return tx.Commit()
}

// SetWalletStatus updates the status of a wallet in PostgreSQL.
func (p *PostgresService) SetWalletStatus(ctx context.Context, walletID string, status WalletStatus) error {
	query := `
		UPDATE ap_wallet
		SET status = $1, updated_at = $2
		WHERE wallet_id = $3;
	`
	res, err := p.db.ExecContext(ctx, query, string(status), time.Now(), walletID)
	if err != nil {
		return fmt.Errorf("failed to update wallet status: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrWalletNotFound
	}
	return nil
}
