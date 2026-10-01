// Token-ledger and checkpoint implementation from 3fd9544, retained as an independent regression oracle.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type baselineTokenReceipt = TokenReceipt

const baselineTokenReceiptContext = "ksync-token-receipt-v1"

type baselineTokenEventInput struct {
	AccountID   string
	AppID       string
	EventType   string
	AmountDelta int64
	SourceType  string
	SourceRef   string
}

type baselineTokenReceiptPayload struct {
	ReceiptID    string `json:"receipt_id"`
	IssuerID     string `json:"issuer_id"`
	AssetID      string `json:"asset_id"`
	AccountID    string `json:"account_id"`
	AppID        string `json:"app_id,omitempty"`
	EventType    string `json:"event_type"`
	AmountDelta  int64  `json:"amount_delta"`
	LedgerSeq    int64  `json:"ledger_seq"`
	PreviousHash string `json:"previous_hash"`
	EventHash    string `json:"event_hash"`
	CreatedAt    string `json:"created_at"`
	SourceType   string `json:"source_type"`
	SourceRef    string `json:"source_ref"`
}

type baselineMoneroInvoiceRecord struct {
	AccountID string
	Invoice   MoneroInvoiceResponse
}

func (s *Store) baselineTokenAssets(ctx context.Context) ([]TokenAsset, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT issuer_id,asset_id,display_name,decimals,status
FROM token_assets
ORDER BY issuer_id,asset_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenAsset
	for rows.Next() {
		var item TokenAsset
		if err := rows.Scan(&item.IssuerID, &item.AssetID, &item.DisplayName, &item.Decimals, &item.Status); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) baselineTokenBalance(ctx context.Context, accountID, assetID string) (int64, error) {
	var balance sql.NullInt64
	err := s.Database.QueryRowContext(ctx, `
SELECT SUM(amount_delta)
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2`, accountID, assetID).Scan(&balance)
	if err != nil {
		return 0, err
	}
	if !balance.Valid {
		return 0, nil
	}
	return balance.Int64, nil
}

func (s *Store) baselineTokenAppBalance(ctx context.Context, accountID, assetID, appID string) (int64, error) {
	var balance sql.NullInt64
	err := s.Database.QueryRowContext(ctx, `
SELECT SUM(amount_delta)
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2 AND app_id=?3`, accountID, assetID, appID).Scan(&balance)
	if err != nil {
		return 0, err
	}
	if !balance.Valid {
		return 0, nil
	}
	return balance.Int64, nil
}

func (s *Store) baselineTokenLedger(ctx context.Context, accountID, assetID string, since int64) ([]baselineTokenReceipt, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2 AND ledger_seq>?3
ORDER BY ledger_seq`, accountID, assetID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []baselineTokenReceipt
	for rows.Next() {
		item, err := baselineScanTokenReceipt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) baselineTokenAppLedger(ctx context.Context, accountID, assetID, appID string, since int64) ([]baselineTokenReceipt, error) {
	rows, err := s.Database.QueryContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2 AND app_id=?3 AND ledger_seq>?4
ORDER BY ledger_seq`, accountID, assetID, appID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []baselineTokenReceipt
	for rows.Next() {
		item, err := baselineScanTokenReceipt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) baselineTokenReceipt(ctx context.Context, receiptID string) (baselineTokenReceipt, bool, error) {
	row := s.Database.QueryRowContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE receipt_id=?1`, receiptID)
	receipt, err := baselineScanTokenReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return baselineTokenReceipt{}, false, nil
	}
	if err != nil {
		return baselineTokenReceipt{}, false, err
	}
	return receipt, true, nil
}

type baselineTokenReceiptScanner interface {
	Scan(dest ...any) error
}

func baselineScanTokenReceipt(row baselineTokenReceiptScanner) (baselineTokenReceipt, error) {
	var item baselineTokenReceipt
	err := row.Scan(&item.ReceiptID, &item.IssuerID, &item.AssetID, &item.AccountID,
		&item.AppID, &item.EventType, &item.AmountDelta, &item.LedgerSeq,
		&item.PreviousHash, &item.EventHash, &item.CreatedAt, &item.SourceType,
		&item.SourceRef, &item.Signature)
	return item, err
}

func (s *Store) baselineCreditTokenPayment(ctx context.Context, signer ed25519.PrivateKey, provider, providerPaymentID string, input baselineTokenEventInput) (baselineTokenReceipt, bool, error) {
	if provider == "" || providerPaymentID == "" {
		return baselineTokenReceipt{}, false, errors.New("provider payment id required")
	}
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return baselineTokenReceipt{}, false, err
	}
	defer tx.Rollback()
	receipt, created, err := baselineCreditTokenPaymentTx(ctx, tx, signer, provider, providerPaymentID, input)
	if err != nil {
		return baselineTokenReceipt{}, false, err
	}
	return receipt, created, tx.Commit()
}

func baselineCreditTokenPaymentTx(ctx context.Context, tx *sql.Tx, signer ed25519.PrivateKey, provider, providerPaymentID string, input baselineTokenEventInput) (baselineTokenReceipt, bool, error) {
	var existingReceiptID string
	err := tx.QueryRowContext(ctx, `
SELECT receipt_id
FROM token_processed_payments
WHERE provider=?1 AND provider_payment_id=?2`, provider, providerPaymentID).Scan(&existingReceiptID)
	if err == nil {
		var existingAccountID, existingAssetID string
		var existingAmount int64
		if err := tx.QueryRowContext(ctx, `
SELECT account_id,asset_id,amount
FROM token_processed_payments
WHERE provider=?1 AND provider_payment_id=?2`, provider, providerPaymentID).Scan(
			&existingAccountID, &existingAssetID, &existingAmount); err != nil {
			return baselineTokenReceipt{}, false, err
		}
		if existingAccountID != input.AccountID || existingAssetID != AssetID || existingAmount != input.AmountDelta {
			return baselineTokenReceipt{}, false, errors.New("provider payment id collision")
		}
		receipt, found, err := baselineTokenReceiptByIDTx(ctx, tx, existingReceiptID)
		if err != nil {
			return baselineTokenReceipt{}, false, err
		}
		if !found {
			return baselineTokenReceipt{}, false, errors.New("processed payment receipt missing")
		}
		return receipt, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return baselineTokenReceipt{}, false, err
	}

	receipt, err := baselineInsertTokenEventTx(ctx, tx, signer, input)
	if err != nil {
		return baselineTokenReceipt{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_processed_payments(provider,provider_payment_id,account_id,asset_id,amount,receipt_id)
VALUES(?1,?2,?3,?4,?5,?6)`, provider, providerPaymentID, input.AccountID,
		AssetID, input.AmountDelta, receipt.ReceiptID); err != nil {
		return baselineTokenReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s *Store) baselineSpendTokens(ctx context.Context, signer ed25519.PrivateKey, input baselineTokenEventInput, idempotencyKey string) (baselineTokenReceipt, int64, bool, error) {
	if input.AmountDelta >= 0 {
		return baselineTokenReceipt{}, 0, false, errors.New("spend amount must be negative")
	}
	tx, err := s.Database.BeginTx(ctx, nil)
	if err != nil {
		return baselineTokenReceipt{}, 0, false, err
	}
	defer tx.Rollback()

	requestHash := baselineTokenSpendRequestHash(input)
	var existingReceiptID string
	var existingRequestHash string
	err = tx.QueryRowContext(ctx, `
SELECT receipt_id,request_hash
FROM token_spend_nonces
WHERE account_id=?1 AND app_id=?2 AND idempotency_key=?3`,
		input.AccountID, input.AppID, idempotencyKey).Scan(&existingReceiptID, &existingRequestHash)
	if err == nil {
		if existingRequestHash != "" && existingRequestHash != requestHash {
			return baselineTokenReceipt{}, 0, false, errors.New("idempotency key reused for different spend")
		}
		receipt, found, err := baselineTokenReceiptByIDTx(ctx, tx, existingReceiptID)
		if err != nil {
			return baselineTokenReceipt{}, 0, false, err
		}
		if !found {
			return baselineTokenReceipt{}, 0, false, errors.New("spend receipt missing")
		}
		balance, err := baselineTokenBalanceTx(ctx, tx, input.AccountID, AssetID)
		if err != nil {
			return baselineTokenReceipt{}, 0, false, err
		}
		return receipt, balance, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return baselineTokenReceipt{}, 0, false, err
	}

	balance, err := baselineTokenBalanceTx(ctx, tx, input.AccountID, AssetID)
	if err != nil {
		return baselineTokenReceipt{}, 0, false, err
	}
	if balance+input.AmountDelta < 0 {
		return baselineTokenReceipt{}, balance, false, errors.New("insufficient balance")
	}
	receipt, err := baselineInsertTokenEventTx(ctx, tx, signer, input)
	if err != nil {
		return baselineTokenReceipt{}, 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_spend_nonces(account_id,app_id,idempotency_key,receipt_id,request_hash)
VALUES(?1,?2,?3,?4,?5)`, input.AccountID, input.AppID, idempotencyKey, receipt.ReceiptID, requestHash); err != nil {
		return baselineTokenReceipt{}, 0, false, err
	}
	balance += input.AmountDelta
	return receipt, balance, true, tx.Commit()
}

func baselineTokenSpendRequestHash(input baselineTokenEventInput) string {
	payload, _ := json.Marshal(input)
	return Signing_SHA256Hex(payload)
}

func baselineInsertTokenEventTx(ctx context.Context, tx *sql.Tx, signer ed25519.PrivateKey, input baselineTokenEventInput) (baselineTokenReceipt, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return baselineTokenReceipt{}, errTokenIssuerReadOnly
	}
	if err := baselineValidateTokenEventInput(input); err != nil {
		return baselineTokenReceipt{}, err
	}
	var previousHash sql.NullString
	var previousSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
SELECT ledger_seq,event_hash
FROM token_ledger
ORDER BY ledger_seq DESC
LIMIT 1`).Scan(&previousSeq, &previousHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return baselineTokenReceipt{}, err
	}
	ledgerSeq := int64(1)
	if previousSeq.Valid {
		ledgerSeq = previousSeq.Int64 + 1
	}
	resource := ResourceId_New()
	receiptID, err := resource.Value, resource.Error
	if err != nil {
		return baselineTokenReceipt{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	payload := baselineTokenReceiptPayload{
		ReceiptID:    receiptID,
		IssuerID:     IssuerID,
		AssetID:      AssetID,
		AccountID:    input.AccountID,
		AppID:        input.AppID,
		EventType:    input.EventType,
		AmountDelta:  input.AmountDelta,
		LedgerSeq:    ledgerSeq,
		PreviousHash: previousHash.String,
		CreatedAt:    createdAt,
		SourceType:   input.SourceType,
		SourceRef:    input.SourceRef,
	}
	eventHash := baselineHashTokenReceiptPayload(payload)
	payload.EventHash = eventHash
	signature := ed25519.Sign(signer, baselineCanonicalTokenReceiptPayload(payload))
	receipt := baselineTokenReceiptFromPayload(payload, signature)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_ledger(receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,
	ledger_seq,previous_hash,event_hash,signature,created_at,source_type,source_ref)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)`,
		receipt.ReceiptID, receipt.IssuerID, receipt.AssetID, receipt.AccountID,
		receipt.AppID, receipt.EventType, receipt.AmountDelta, receipt.LedgerSeq,
		receipt.PreviousHash, receipt.EventHash, receipt.Signature, receipt.CreatedAt,
		receipt.SourceType, receipt.SourceRef); err != nil {
		return baselineTokenReceipt{}, err
	}
	return receipt, nil
}

func baselineValidateTokenEventInput(input baselineTokenEventInput) error {
	if !Identity_ValidUserID(input.AccountID) {
		return errors.New("invalid account_id")
	}
	if input.AppID != "" && !Identity_ValidNamespace(input.AppID) {
		return errors.New("invalid app_id")
	}
	if input.EventType != "credit" && input.EventType != "debit" {
		return errors.New("invalid event_type")
	}
	if input.AmountDelta == 0 {
		return errors.New("amount required")
	}
	if input.EventType == "credit" && input.AmountDelta < 0 {
		return errors.New("credit amount must be positive")
	}
	if input.EventType == "debit" && input.AmountDelta > 0 {
		return errors.New("debit amount must be negative")
	}
	if !Identity_ValidNamespace(input.SourceType) || strings.TrimSpace(input.SourceRef) == "" || len(input.SourceRef) > 256 {
		return errors.New("invalid source")
	}
	return nil
}

func baselineTokenReceiptByIDTx(ctx context.Context, tx *sql.Tx, receiptID string) (baselineTokenReceipt, bool, error) {
	row := tx.QueryRowContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE receipt_id=?1`, receiptID)
	receipt, err := baselineScanTokenReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return baselineTokenReceipt{}, false, nil
	}
	if err != nil {
		return baselineTokenReceipt{}, false, err
	}
	return receipt, true, nil
}

func baselineTokenBalanceTx(ctx context.Context, tx *sql.Tx, accountID, assetID string) (int64, error) {
	var balance sql.NullInt64
	err := tx.QueryRowContext(ctx, `
SELECT SUM(amount_delta)
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2`, accountID, assetID).Scan(&balance)
	if err != nil {
		return 0, err
	}
	if !balance.Valid {
		return 0, nil
	}
	return balance.Int64, nil
}

func baselineTokenReceiptFromPayload(payload baselineTokenReceiptPayload, signature []byte) baselineTokenReceipt {
	return baselineTokenReceipt{
		ReceiptID:    payload.ReceiptID,
		IssuerID:     payload.IssuerID,
		AssetID:      payload.AssetID,
		AccountID:    payload.AccountID,
		AppID:        payload.AppID,
		EventType:    payload.EventType,
		AmountDelta:  payload.AmountDelta,
		LedgerSeq:    payload.LedgerSeq,
		PreviousHash: payload.PreviousHash,
		EventHash:    payload.EventHash,
		CreatedAt:    payload.CreatedAt,
		SourceType:   payload.SourceType,
		SourceRef:    payload.SourceRef,
		Signature:    hex.EncodeToString(signature),
	}
}

func baselineCanonicalTokenReceiptPayload(payload baselineTokenReceiptPayload) []byte {
	data, _ := json.Marshal(payload)
	return append([]byte(baselineTokenReceiptContext+"\n"), data...)
}

func baselineHashTokenReceiptPayload(payload baselineTokenReceiptPayload) string {
	payload.EventHash = ""
	sum := sha256.Sum256(baselineCanonicalTokenReceiptPayload(payload))
	return hex.EncodeToString(sum[:])
}

func baselineValidTokenReceiptSignature(publicKey ed25519.PublicKey, receipt baselineTokenReceipt) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload := baselineTokenReceiptPayload{
		ReceiptID:    receipt.ReceiptID,
		IssuerID:     receipt.IssuerID,
		AssetID:      receipt.AssetID,
		AccountID:    receipt.AccountID,
		AppID:        receipt.AppID,
		EventType:    receipt.EventType,
		AmountDelta:  receipt.AmountDelta,
		LedgerSeq:    receipt.LedgerSeq,
		PreviousHash: receipt.PreviousHash,
		EventHash:    receipt.EventHash,
		CreatedAt:    receipt.CreatedAt,
		SourceType:   receipt.SourceType,
		SourceRef:    receipt.SourceRef,
	}
	return receipt.EventHash == baselineHashTokenReceiptPayload(payload) &&
		ed25519.Verify(publicKey, baselineCanonicalTokenReceiptPayload(payload), signature)
}

func (s *Store) baselineCreateTokenCheckpoint(ctx context.Context, signer ed25519.PrivateKey) (TokenCheckpoint, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return TokenCheckpoint{}, errTokenIssuerReadOnly
	}
	rows, err := s.Database.QueryContext(ctx, `
SELECT ledger_seq,event_hash
FROM token_ledger
WHERE issuer_id=?1 AND asset_id=?2
ORDER BY ledger_seq`, IssuerID, AssetID)
	if err != nil {
		return TokenCheckpoint{}, err
	}
	defer rows.Close()
	root := bytes.NewBuffer(nil)
	var seq int64
	for rows.Next() {
		var hash string
		if err := rows.Scan(&seq, &hash); err != nil {
			return TokenCheckpoint{}, err
		}
		root.WriteString(hash)
		root.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		return TokenCheckpoint{}, err
	}
	sum := sha256.Sum256(root.Bytes())
	ledgerRoot := hex.EncodeToString(sum[:])
	message := []byte(fmt.Sprintf("ksync-token-checkpoint-v1\n%s\n%s\n%d\n%s\n",
		IssuerID, AssetID, seq, ledgerRoot))
	signature := hex.EncodeToString(ed25519.Sign(signer, message))
	_, err = s.Database.ExecContext(ctx, `
INSERT INTO token_checkpoints(ledger_seq,issuer_id,asset_id,ledger_root,signature)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(ledger_seq) DO UPDATE SET
	ledger_root=excluded.ledger_root,
	signature=excluded.signature,
	created_at=CURRENT_TIMESTAMP`, seq, IssuerID, AssetID, ledgerRoot, signature)
	if err != nil {
		return TokenCheckpoint{}, err
	}
	checkpoint, found, err := s.baselineLatestTokenCheckpoint(ctx)
	if err != nil || !found {
		return TokenCheckpoint{}, err
	}
	return checkpoint, nil
}

func (s *Store) baselineLatestTokenCheckpoint(ctx context.Context) (TokenCheckpoint, bool, error) {
	var out TokenCheckpoint
	err := s.Database.QueryRowContext(ctx, `
SELECT ledger_seq,issuer_id,asset_id,ledger_root,signature,created_at
FROM token_checkpoints
ORDER BY ledger_seq DESC
LIMIT 1`).Scan(&out.LedgerSeq, &out.IssuerID, &out.AssetID, &out.LedgerRoot, &out.Signature, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenCheckpoint{}, false, nil
	}
	if err != nil {
		return TokenCheckpoint{}, false, err
	}
	return out, true, nil
}
