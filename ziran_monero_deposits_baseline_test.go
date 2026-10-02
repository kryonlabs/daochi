package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func baselineHandleMoneroAddress(s *Server, w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.TokenDirectPurchasesEnabled || !MoneroWallet_ValidRate(s.Cfg) || strings.TrimSpace(s.Cfg.MoneroWalletRPCURL) == "" {
		Response_Error(w, http.StatusServiceUnavailable, "monero purchases disabled")
		return
	}
	if !s.allowRequest(r, "monero-address:"+ClientAddress_FromRequest(r), 60, time.Hour) {
		Response_Error(w, http.StatusTooManyRequests, "too many address requests")
		return
	}

	ref := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/purchases/monero/address/"))
	var accountID string
	if r.URL.Path == "/api/v1/tokens/purchases/monero/address" || ref == "" {
		var ok bool
		accountID, ok = s.baselineBearerUser(w, r)
		if !ok {
			return
		}
	} else {
		var found bool
		var err error
		accountID, found, err = s.Store.ResolveAccountRef(r.Context(), ref)
		if err != nil {
			slog.Error("resolve monero recipient", "error", err)
			Response_Error(w, http.StatusInternalServerError, "recipient lookup failed")
			return
		}
		if !found {
			Response_Error(w, http.StatusNotFound, "recipient not found")
			return
		}
	}

	// Serialize allocation per account (the store row's primary key is the
	// real guard); different accounts must not block each other behind one
	// wallet RPC.
	lockAny, _ := s.MoneroAddressLocks.LoadOrStore(accountID, &sync.Mutex{})
	addressLock := lockAny.(*sync.Mutex)
	addressLock.Lock()
	address, found, err := baselineMoneroAccountAddress(s.Store, r.Context(), accountID)
	if err == nil && !found {
		address, err = baselineCreateMoneroAccountAddress(s.Store, r.Context(), accountID, s.Cfg)
	}
	addressLock.Unlock()
	if err != nil {
		slog.Error("allocate monero account address", "account", LogSafety_LogText(accountID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "monero address unavailable")
		return
	}
	network := strings.ToLower(strings.TrimSpace(s.Cfg.MoneroNetwork))
	if network != "mainnet" && network != "stagenet" && network != "testnet" {
		network = "mainnet"
	}
	Response_JSON(w, http.StatusOK, MoneroAddressResponse{
		AccountID:             address.AccountID,
		Alias:                 address.Alias,
		ProfileIcon:           address.ProfileIcon,
		AssetID:               AssetID,
		Address:               address.Address,
		URI:                   "monero:" + url.PathEscape(address.Address),
		Network:               network,
		ConfirmationsRequired: MoneroWallet_ConfirmationsRequired(s.Cfg),
		MinimumAtomicAmount:   MoneroWallet_MinimumAtomicAmount(s.Cfg),
		Rate: MoneroRate{
			AtomicAmount: s.Cfg.MoneroRateAtomicAmount,
			TokenUnits:   s.Cfg.MoneroRateTokenUnits,
		},
	})
}

func baselineHandleMoneroDeposits(s *Server, w http.ResponseWriter, r *http.Request) {
	accountID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	deposits, err := baselineMoneroDeposits(s.Store, r.Context(), accountID, 100)
	if err != nil {
		slog.Error("list monero deposits", "account", LogSafety_LogText(accountID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "monero deposits unavailable")
		return
	}
	Response_JSON(w, http.StatusOK, MoneroDepositsResponse{Deposits: deposits})
}

func baselineMoneroAccountAddress(s *Store, ctx context.Context, accountID string) (MoneroAccountAddress, bool, error) {
	var out MoneroAccountAddress
	err := s.Database.QueryRowContext(ctx, `
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

func baselineCreateMoneroAccountAddress(s *Store, ctx context.Context, accountID string, cfg Config) (MoneroAccountAddress, error) {
	if !Identity_ValidUserID(accountID) {
		return MoneroAccountAddress{}, errors.New("invalid account id")
	}
	var exists int
	if err := s.Database.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM server_users WHERE user_id_hash=?1)`, accountID).Scan(&exists); err != nil {
		return MoneroAccountAddress{}, err
	}
	if exists == 0 {
		return MoneroAccountAddress{}, ErrSyncUserNotFound
	}
	resource := ResourceId_New()
	allocationID, err := resource.Value, resource.Error
	if err != nil {
		return MoneroAccountAddress{}, err
	}
	allocated := MoneroWallet_CreateAddress(ctx, cfg, "daochi-account-"+allocationID, errPaymentUnavailable)
	address, index, err := allocated.Address, allocated.Index, allocated.Error
	if err != nil {
		return MoneroAccountAddress{}, err
	}
	if _, err := s.Database.ExecContext(ctx, `
INSERT INTO monero_account_addresses(account_id,account_index,address_index,address,allocation_id)
VALUES(?1,0,?2,?3,?4)`, accountID, index, address, allocationID); err != nil {
		if existing, found, lookupErr := baselineMoneroAccountAddress(s, ctx, accountID); lookupErr == nil && found {
			return existing, nil
		}
		return MoneroAccountAddress{}, err
	}
	out, _, err := baselineMoneroAccountAddress(s, ctx, accountID)
	return out, err
}

// MoneroScanHeight returns the last wallet height whose transfers were
// already scanned; 0 means "never scanned".
func baselineMoneroScanHeight(s *Store, ctx context.Context) (int64, error) {
	var height int64
	err := s.Database.QueryRowContext(ctx,
		`SELECT last_height FROM monero_wallet_state WHERE wallet_id='default'`).Scan(&height)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return height, err
}

// SaveMoneroScanHeight advances the scan bookmark; it never moves
// backwards, so a reorg cannot skip transfers.
func baselineSaveMoneroScanHeight(s *Store, ctx context.Context, height int64) error {
	if height <= 0 {
		return nil
	}
	_, err := s.Database.ExecContext(ctx, `
INSERT INTO monero_wallet_state(wallet_id,last_height,updated_at)
VALUES('default',?1,?2)
ON CONFLICT(wallet_id) DO UPDATE SET
	last_height=MAX(monero_wallet_state.last_height,excluded.last_height),
	updated_at=excluded.updated_at`, height, Timestamp_CanonicalNow())
	return err
}

func baselineMoneroAddressOwners(s *Store, ctx context.Context) (map[[2]int]string, error) {
	rows, err := s.Database.QueryContext(ctx, `
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

// listMoneroTransfers returns incoming transfers for the whole wallet
// without rescanning the entire history every poll: confirmed transfers
// are requested from the persisted scan bookmark onward, pool transfers
// (height 0, filtered out by min_height) are fetched separately.
func baselineListMoneroTransfers(s *Server, ctx context.Context) ([]WalletTransfer, error) {
	bookmark, err := baselineMoneroScanHeight(s.Store, ctx)
	if err != nil {
		return nil, err
	}
	var confirmed struct {
		In      []WalletTransfer `json:"in"`
		Pending []WalletTransfer `json:"pending"`
	}
	if err := MoneroWallet_Request(ctx, s.Cfg, "get_transfers", map[string]any{
		"in": true, "pending": true, "failed": false, "account_index": 0,
		"min_height": bookmark,
	}, &confirmed, errPaymentUnavailable); err != nil {
		return nil, err
	}
	var pool struct {
		Pool []WalletTransfer `json:"pool"`
	}
	if err := MoneroWallet_Request(ctx, s.Cfg, "get_transfers", map[string]any{
		"pool": true, "account_index": 0,
	}, &pool, errPaymentUnavailable); err != nil {
		return nil, err
	}
	maxHeight := bookmark
	var walletHeight struct {
		Height int64 `json:"height"`
	}
	if err := MoneroWallet_Request(ctx, s.Cfg, "get_height", map[string]any{}, &walletHeight, errPaymentUnavailable); err == nil && walletHeight.Height > maxHeight {
		maxHeight = walletHeight.Height
	}
	for _, transfer := range confirmed.In {
		if transfer.Height > maxHeight {
			maxHeight = transfer.Height
		}
	}
	if maxHeight > bookmark {
		if err := baselineSaveMoneroScanHeight(s.Store, ctx, maxHeight); err != nil {
			return nil, err
		}
	}
	byPayment := make(map[string]WalletTransfer, len(pool.Pool)+len(confirmed.In)+len(confirmed.Pending))
	for _, transfer := range append(pool.Pool, append(confirmed.In, confirmed.Pending...)...) {
		key := fmt.Sprintf("%s:%d:%d", transfer.TxID, transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
		if previous, ok := byPayment[key]; !ok || transfer.Confirmations >= previous.Confirmations {
			byPayment[key] = transfer
		}
	}
	out := make([]WalletTransfer, 0, len(byPayment))
	for _, transfer := range byPayment {
		out = append(out, transfer)
	}
	return out, nil
}

func baselineReconcileMoneroAccountDeposits(s *Server, ctx context.Context) error {
	if !MoneroWallet_ValidRate(s.Cfg) {
		return nil
	}
	owners, err := baselineMoneroAddressOwners(s.Store, ctx)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		return nil
	}
	transfers, err := baselineListMoneroTransfers(s, ctx)
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
		if err := baselineSettleMoneroAccountDeposit(s, ctx, accountID, transfer); err != nil {
			slog.Warn("monero account deposit settlement failed", "account", LogSafety_LogText(accountID),
				"tx", LogSafety_LogText(transfer.TxID), "error", err)
		}
	}
	return nil
}

func baselineSettleMoneroAccountDeposit(s *Server, ctx context.Context, accountID string, transfer WalletTransfer) error {
	conversion := MoneroWallet_TokenUnits(transfer.Amount, s.Cfg.MoneroRateAtomicAmount, s.Cfg.MoneroRateTokenUnits)
	units, conversionErr := conversion.Value, conversion.Error
	status := "confirming"
	switch {
	case transfer.DoubleSpendSeen:
		status = "double_spend"
	case transfer.Amount < MoneroWallet_MinimumAtomicAmount(s.Cfg) || conversionErr != nil || units <= 0:
		status = "below_minimum"
	case transfer.Confirmations >= MoneroWallet_ConfirmationsRequired(s.Cfg) && !transfer.Locked && transfer.UnlockTime == 0:
		status = "confirmed"
	}
	deposit, err := baselineUpsertMoneroDeposit(s.Store, ctx, accountID, transfer, status, s.Cfg)
	if err != nil || status != "confirmed" || deposit.Receipt != nil {
		return err
	}
	issuer := TokenPolicy_Issuer(s.Cfg, errTokenIssuerReadOnly)
	signer, err := issuer.Value, issuer.Error
	if err != nil {
		return err
	}
	_, _, err = baselineCreditMoneroDeposit(s.Store, ctx, signer, transfer.TxID,
		transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
	return err
}

func baselineUpsertMoneroDeposit(s *Store, ctx context.Context, accountID string, transfer WalletTransfer, status string, cfg Config) (MoneroDeposit, error) {
	conversion := MoneroWallet_TokenUnits(transfer.Amount, cfg.MoneroRateAtomicAmount, cfg.MoneroRateTokenUnits)
	units := conversion.Value
	_, err := s.Database.ExecContext(ctx, `
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
	return baselineMoneroDeposit(s, ctx, transfer.TxID, transfer.SubaddrIndex.Major, transfer.SubaddrIndex.Minor)
}

func baselineCreditMoneroDeposit(s *Store, ctx context.Context, signer ed25519.PrivateKey, txID string, major, minor int) (TokenReceipt, bool, error) {
	tx, err := s.Database.BeginTx(ctx, nil)
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
		receiptResult := TokenLedger_ByIDTx(tx, ctx, receiptID)
		receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
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
	paymentResult := TokenLedger_CreditPaymentTx(tx, ctx, signer, "monero_account", paymentID, TokenEventInput{
		AccountID: accountID, EventType: "credit", AmountDelta: tokenUnits,
		SourceType: "monero_account", SourceRef: paymentID,
	}, errTokenIssuerReadOnly)
	receipt, created, err := paymentResult.Value, paymentResult.Created, paymentResult.Error
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
	if AccountState_Affected(result) != 1 {
		return TokenReceipt{}, false, errors.New("monero deposit settlement race")
	}
	return receipt, created, tx.Commit()
}

func baselineMoneroDeposit(s *Store, ctx context.Context, txID string, major, minor int) (MoneroDeposit, error) {
	row := s.Database.QueryRowContext(ctx, `
SELECT tx_id,account_id,amount_atomic,token_units,block_height,confirmations,status,first_seen_at,
	confirmed_at,credited_at,receipt_id,account_index,address_index,unlock_time,locked,double_spend_seen,
	rate_atomic_amount,rate_token_units
FROM monero_deposits WHERE tx_id=?1 AND account_index=?2 AND address_index=?3`, txID, major, minor)
	return baselineScanMoneroDeposit(ctx, s, row)
}

func baselineMoneroDeposits(s *Store, ctx context.Context, accountID string, limit int) ([]MoneroDeposit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Database.QueryContext(ctx, `
SELECT tx_id,account_id,amount_atomic,token_units,block_height,confirmations,status,first_seen_at,
	confirmed_at,credited_at,receipt_id,account_index,address_index,unlock_time,locked,double_spend_seen,
	rate_atomic_amount,rate_token_units
FROM monero_deposits WHERE account_id=?1 ORDER BY first_seen_at DESC LIMIT ?2`, accountID, limit)
	if err != nil {
		return nil, err
	}
	var out []MoneroDeposit
	for rows.Next() {
		item, err := baselineScanMoneroDeposit(ctx, nil, rows)
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
		receiptResult := TokenLedger_ByID(s.Database, ctx, out[i].ReceiptID)
		receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
		if err != nil {
			return nil, err
		}
		if found {
			out[i].Receipt = &receipt
		}
	}
	return out, nil
}

type baselineMoneroDepositScanner interface {
	Scan(dest ...any) error
}

func baselineScanMoneroDeposit(ctx context.Context, store *Store, row baselineMoneroDepositScanner) (MoneroDeposit, error) {
	var out MoneroDeposit
	err := row.Scan(&out.TxID, &out.AccountID, &out.AmountAtomic, &out.TokenUnits, &out.BlockHeight,
		&out.Confirmations, &out.Status, &out.FirstSeenAt, &out.ConfirmedAt, &out.CreditedAt,
		&out.ReceiptID, &out.AccountIndex, &out.AddressIndex, &out.UnlockTime, &out.Locked,
		&out.DoubleSpendSeen, &out.RateAtomic, &out.RateTokenUnits)
	if err != nil {
		return MoneroDeposit{}, err
	}
	if store != nil && out.ReceiptID != "" {
		receiptResult := TokenLedger_ByID(store.Database, ctx, out.ReceiptID)
		receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
		if err != nil {
			return MoneroDeposit{}, err
		}
		if found {
			out.Receipt = &receipt
		}
	}
	return out, nil
}
