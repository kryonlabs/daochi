package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type moneroTransferRPC struct {
	TxID            string `json:"txid"`
	Amount          int64  `json:"amount"`
	Confirmations   int64  `json:"confirmations"`
	Height          int64  `json:"height"`
	UnlockTime      int64  `json:"unlock_time"`
	Locked          bool   `json:"locked"`
	DoubleSpendSeen bool   `json:"double_spend_seen"`
	SubaddrIndex    struct {
		Major int `json:"major"`
		Minor int `json:"minor"`
	} `json:"subaddr_index"`
}

func validMoneroRate(cfg Config) bool {
	return cfg.MoneroRateAtomicAmount > 0 && cfg.MoneroRateTokenUnits > 0
}

func moneroConfirmationsRequired(cfg Config) int64 {
	if cfg.MoneroConfirmationsRequired > 0 {
		return cfg.MoneroConfirmationsRequired
	}
	return 10
}

func moneroMinimumAtomicAmount(cfg Config) int64 {
	if cfg.MoneroMinimumAtomicAmount > 0 {
		return cfg.MoneroMinimumAtomicAmount
	}
	return 1
}

func moneroTokenUnits(amount, rateAtomic, rateTokens int64) (int64, error) {
	if amount <= 0 || rateAtomic <= 0 || rateTokens <= 0 {
		return 0, errors.New("invalid monero conversion")
	}
	value := new(big.Int).Mul(big.NewInt(amount), big.NewInt(rateTokens))
	value.Div(value, big.NewInt(rateAtomic))
	if !value.IsInt64() {
		return 0, errors.New("monero conversion overflow")
	}
	return value.Int64(), nil
}

func (s *Server) handleMoneroAddress(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.TokenDirectPurchasesEnabled || !validMoneroRate(s.cfg) || strings.TrimSpace(s.cfg.MoneroWalletRPCURL) == "" {
		writeError(w, http.StatusServiceUnavailable, "monero purchases disabled")
		return
	}
	if !s.allowRequest(r, "monero-address:"+clientAddress(r), 60, time.Hour) {
		writeError(w, http.StatusTooManyRequests, "too many address requests")
		return
	}

	ref := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/purchases/monero/address/"))
	var accountID string
	if r.URL.Path == "/api/v1/tokens/purchases/monero/address" || ref == "" {
		var ok bool
		accountID, ok = s.bearerUser(w, r)
		if !ok {
			return
		}
	} else {
		var found bool
		var err error
		accountID, found, err = s.store.ResolveAccountRef(r.Context(), ref)
		if err != nil {
			slog.Error("resolve monero recipient", "error", err)
			writeError(w, http.StatusInternalServerError, "recipient lookup failed")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "recipient not found")
			return
		}
	}

	s.moneroAddressMu.Lock()
	address, found, err := s.store.MoneroAccountAddress(r.Context(), accountID)
	if err == nil && !found {
		address, err = s.store.CreateMoneroAccountAddress(r.Context(), accountID, s.cfg)
	}
	s.moneroAddressMu.Unlock()
	if err != nil {
		slog.Error("allocate monero account address", "account", logText(accountID), "error", err)
		writeError(w, http.StatusInternalServerError, "monero address unavailable")
		return
	}
	network := strings.ToLower(strings.TrimSpace(s.cfg.MoneroNetwork))
	if network != "mainnet" && network != "stagenet" && network != "testnet" {
		network = "mainnet"
	}
	writeJSON(w, http.StatusOK, MoneroAddressResponse{
		AccountID:             address.AccountID,
		Alias:                 address.Alias,
		ProfileIcon:           address.ProfileIcon,
		AssetID:               waoziTokenAssetID,
		Address:               address.Address,
		URI:                   "monero:" + url.PathEscape(address.Address),
		Network:               network,
		ConfirmationsRequired: moneroConfirmationsRequired(s.cfg),
		MinimumAtomicAmount:   moneroMinimumAtomicAmount(s.cfg),
		Rate: MoneroRate{
			AtomicAmount: s.cfg.MoneroRateAtomicAmount,
			TokenUnits:   s.cfg.MoneroRateTokenUnits,
		},
	})
}

func (s *Server) handleMoneroDeposits(w http.ResponseWriter, r *http.Request) {
	accountID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	deposits, err := s.store.MoneroDeposits(r.Context(), accountID, 100)
	if err != nil {
		slog.Error("list monero deposits", "account", logText(accountID), "error", err)
		writeError(w, http.StatusInternalServerError, "monero deposits unavailable")
		return
	}
	writeJSON(w, http.StatusOK, MoneroDepositsResponse{Deposits: deposits})
}

func (s *Store) MoneroAccountAddress(ctx context.Context, accountID string) (MoneroAccountAddress, bool, error) {
	var out MoneroAccountAddress
	err := s.db.QueryRowContext(ctx, `
SELECT m.account_id,COALESCE(u.alias,''),COALESCE(u.profile_icon,0),m.address,m.account_index,m.address_index,m.created_at
FROM monero_account_addresses m
LEFT JOIN server_users u ON u.user_id_hash=m.account_id
WHERE m.account_id=?1 AND m.disabled_at=''`, accountID).Scan(
		&out.AccountID, &out.Alias, &out.ProfileIcon, &out.Address,
		&out.AccountIndex, &out.AddressIndex, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MoneroAccountAddress{}, false, nil
	}
	return out, err == nil, err
}

func (s *Store) CreateMoneroAccountAddress(ctx context.Context, accountID string, cfg Config) (MoneroAccountAddress, error) {
	if !validUserID(accountID) {
		return MoneroAccountAddress{}, errors.New("invalid account id")
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_users WHERE user_id_hash=?1)`, accountID).Scan(&exists); err != nil {
		return MoneroAccountAddress{}, err
	}
	if exists == 0 {
		return MoneroAccountAddress{}, ErrSyncUserNotFound
	}
	allocationID, err := randomResourceID()
	if err != nil {
		return MoneroAccountAddress{}, err
	}
	address, index, err := createMoneroSubaddress(ctx, cfg, "daochi-account-"+allocationID)
	if err != nil {
		return MoneroAccountAddress{}, err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO monero_account_addresses(account_id,account_index,address_index,address,allocation_id)
VALUES(?1,0,?2,?3,?4)`, accountID, index, address, allocationID); err != nil {
		if existing, found, lookupErr := s.MoneroAccountAddress(ctx, accountID); lookupErr == nil && found {
			return existing, nil
		}
		return MoneroAccountAddress{}, err
	}
	out, _, err := s.MoneroAccountAddress(ctx, accountID)
	return out, err
}

func (s *Store) moneroAddressOwners(ctx context.Context) (map[[2]int]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT account_index,address_index,account_id
FROM monero_account_addresses
WHERE disabled_at=''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[[2]int]string)
	for rows.Next() {
		var major, minor int
		var accountID string
		if err := rows.Scan(&major, &minor, &accountID); err != nil {
			return nil, err
		}
		out[[2]int{major, minor}] = accountID
	}
	return out, rows.Err()
}

func listMoneroTransfers(ctx context.Context, cfg Config) ([]moneroTransferRPC, error) {
	var result struct {
		In   []moneroTransferRPC `json:"in"`
		Pool []moneroTransferRPC `json:"pool"`
	}
	if err := moneroRPC(ctx, cfg, "get_transfers", map[string]any{
		"in": true, "pool": true, "pending": true, "failed": false, "account_index": 0,
	}, &result); err != nil {
		return nil, err
	}
	byPayment := make(map[string]moneroTransferRPC, len(result.Pool)+len(result.In))
	for _, transfer := range append(result.Pool, result.In...) {
		key := fmt.Sprintf("%s:%d:%d", transfer.TxID, transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
		if previous, ok := byPayment[key]; !ok || transfer.Confirmations >= previous.Confirmations {
			byPayment[key] = transfer
		}
	}
	out := make([]moneroTransferRPC, 0, len(byPayment))
	for _, transfer := range byPayment {
		out = append(out, transfer)
	}
	return out, nil
}

func (s *Server) reconcileMoneroAccountDeposits(ctx context.Context) error {
	if !validMoneroRate(s.cfg) {
		return nil
	}
	owners, err := s.store.moneroAddressOwners(ctx)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		return nil
	}
	transfers, err := listMoneroTransfers(ctx, s.cfg)
	if err != nil {
		return err
	}
	for _, transfer := range transfers {
		if transfer.TxID == "" || transfer.Amount <= 0 {
			continue
		}
		accountID, known := owners[[2]int{transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor}]
		if !known {
			continue
		}
		if err := s.settleMoneroAccountDeposit(ctx, accountID, transfer); err != nil {
			slog.Warn("monero account deposit settlement failed", "account", logText(accountID),
				"tx", logText(transfer.TxID), "error", err)
		}
	}
	return nil
}

func (s *Server) settleMoneroAccountDeposit(ctx context.Context, accountID string, transfer moneroTransferRPC) error {
	units, conversionErr := moneroTokenUnits(transfer.Amount, s.cfg.MoneroRateAtomicAmount, s.cfg.MoneroRateTokenUnits)
	status := "confirming"
	switch {
	case transfer.DoubleSpendSeen:
		status = "double_spend"
	case transfer.Amount < moneroMinimumAtomicAmount(s.cfg) || conversionErr != nil || units <= 0:
		status = "below_minimum"
	case transfer.Confirmations >= moneroConfirmationsRequired(s.cfg) && !transfer.Locked && transfer.UnlockTime == 0:
		status = "confirmed"
	}
	deposit, err := s.store.UpsertMoneroDeposit(ctx, accountID, transfer, status, s.cfg)
	if err != nil || status != "confirmed" || deposit.Receipt != nil {
		return err
	}
	signer, err := s.requireTokenIssuer()
	if err != nil {
		return err
	}
	_, _, err = s.store.CreditMoneroDeposit(ctx, signer, transfer.TxID,
		transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
	return err
}

func (s *Store) UpsertMoneroDeposit(ctx context.Context, accountID string, transfer moneroTransferRPC, status string, cfg Config) (MoneroDeposit, error) {
	units, _ := moneroTokenUnits(transfer.Amount, cfg.MoneroRateAtomicAmount, cfg.MoneroRateTokenUnits)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO monero_deposits(tx_id,account_index,address_index,account_id,amount_atomic,block_height,
	confirmations,unlock_time,locked,double_spend_seen,status,rate_atomic_amount,rate_token_units,token_units)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
ON CONFLICT(tx_id,account_index,address_index) DO UPDATE SET
	amount_atomic=excluded.amount_atomic,
	block_height=excluded.block_height,
	confirmations=excluded.confirmations,
	unlock_time=excluded.unlock_time,
	locked=excluded.locked,
	double_spend_seen=excluded.double_spend_seen,
	status=CASE WHEN monero_deposits.status='credited' THEN 'credited' ELSE excluded.status END,
	updated_at=CURRENT_TIMESTAMP`, transfer.TxID, transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor,
		accountID, transfer.Amount, transfer.Height, transfer.Confirmations, transfer.UnlockTime,
		transfer.Locked, transfer.DoubleSpendSeen, status, cfg.MoneroRateAtomicAmount,
		cfg.MoneroRateTokenUnits, units)
	if err != nil {
		return MoneroDeposit{}, err
	}
	return s.moneroDeposit(ctx, transfer.TxID, transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
}

func (s *Store) CreditMoneroDeposit(ctx context.Context, signer ed25519.PrivateKey, txID string, major, minor int) (TokenReceipt, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenReceipt{}, false, err
	}
	defer tx.Rollback()
	var accountID, status, receiptID string
	var tokenUnits int64
	if err := tx.QueryRowContext(ctx, `
SELECT account_id,status,token_units,receipt_id
FROM monero_deposits
WHERE tx_id=?1 AND account_index=?2 AND address_index=?3`, txID, major, minor).Scan(
		&accountID, &status, &tokenUnits, &receiptID); err != nil {
		return TokenReceipt{}, false, err
	}
	if receiptID != "" {
		receipt, found, err := tokenReceiptByIDTx(ctx, tx, receiptID)
		if err != nil {
			return TokenReceipt{}, false, err
		}
		if !found {
			return TokenReceipt{}, false, errors.New("monero deposit receipt missing")
		}
		return receipt, false, tx.Commit()
	}
	if status != "confirmed" || tokenUnits <= 0 {
		return TokenReceipt{}, false, errors.New("monero deposit is not creditable")
	}
	paymentID := fmt.Sprintf("%s:%d:%d", txID, major, minor)
	receipt, created, err := creditTokenPaymentTx(ctx, tx, signer, "monero_account", paymentID, tokenEventInput{
		AccountID: accountID, EventType: "credit", AmountDelta: tokenUnits,
		SourceType: "monero_account", SourceRef: paymentID,
	})
	if err != nil {
		return TokenReceipt{}, false, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE monero_deposits
SET status='credited',receipt_id=?4,confirmed_at=CASE WHEN confirmed_at='' THEN CURRENT_TIMESTAMP ELSE confirmed_at END,
	credited_at=CASE WHEN credited_at='' THEN CURRENT_TIMESTAMP ELSE credited_at END,updated_at=CURRENT_TIMESTAMP
WHERE tx_id=?1 AND account_index=?2 AND address_index=?3 AND receipt_id=''`, txID, major, minor, receipt.ReceiptID)
	if err != nil {
		return TokenReceipt{}, false, err
	}
	if rowsAffected(result) != 1 {
		return TokenReceipt{}, false, errors.New("monero deposit settlement race")
	}
	return receipt, created, tx.Commit()
}

func (s *Store) moneroDeposit(ctx context.Context, txID string, major, minor int) (MoneroDeposit, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT tx_id,account_id,amount_atomic,token_units,block_height,confirmations,status,first_seen_at,
	confirmed_at,credited_at,receipt_id,account_index,address_index,unlock_time,locked,double_spend_seen,
	rate_atomic_amount,rate_token_units
FROM monero_deposits WHERE tx_id=?1 AND account_index=?2 AND address_index=?3`, txID, major, minor)
	return scanMoneroDeposit(ctx, s, row)
}

func (s *Store) MoneroDeposits(ctx context.Context, accountID string, limit int) ([]MoneroDeposit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT tx_id,account_id,amount_atomic,token_units,block_height,confirmations,status,first_seen_at,
	confirmed_at,credited_at,receipt_id,account_index,address_index,unlock_time,locked,double_spend_seen,
	rate_atomic_amount,rate_token_units
FROM monero_deposits WHERE account_id=?1 ORDER BY first_seen_at DESC LIMIT ?2`, accountID, limit)
	if err != nil {
		return nil, err
	}
	var out []MoneroDeposit
	for rows.Next() {
		item, err := scanMoneroDeposit(ctx, nil, rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].ReceiptID == "" {
			continue
		}
		receipt, found, err := s.TokenReceipt(ctx, out[i].ReceiptID)
		if err != nil {
			return nil, err
		}
		if found {
			out[i].Receipt = &receipt
		}
	}
	return out, nil
}

type moneroDepositScanner interface {
	Scan(dest ...any) error
}

func scanMoneroDeposit(ctx context.Context, store *Store, row moneroDepositScanner) (MoneroDeposit, error) {
	var out MoneroDeposit
	err := row.Scan(&out.TxID, &out.AccountID, &out.AmountAtomic, &out.TokenUnits, &out.BlockHeight,
		&out.Confirmations, &out.Status, &out.FirstSeenAt, &out.ConfirmedAt, &out.CreditedAt,
		&out.ReceiptID, &out.AccountIndex, &out.AddressIndex, &out.UnlockTime, &out.Locked,
		&out.DoubleSpendSeen, &out.RateAtomic, &out.RateTokenUnits)
	if err != nil {
		return MoneroDeposit{}, err
	}
	if store != nil && out.ReceiptID != "" {
		receipt, found, err := store.TokenReceipt(ctx, out.ReceiptID)
		if err != nil {
			return MoneroDeposit{}, err
		}
		if found {
			out.Receipt = &receipt
		}
	}
	return out, nil
}
