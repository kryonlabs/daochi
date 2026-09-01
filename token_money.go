package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	waoziIssuerID           = "waozi"
	waoziTokenAssetID       = "waozi:token"
	tokenReceiptContext     = "ksync-token-receipt-v1"
	tokenPermissionSpend    = "spend"
	tokenPermissionPurchase = "purchase"
)

var (
	errTokenIssuerReadOnly = errors.New("token issuer private key unavailable")
	errPaymentUnavailable  = errors.New("payment verifier unavailable")
)

type tokenEventInput struct {
	AccountID   string
	AppID       string
	EventType   string
	AmountDelta int64
	SourceType  string
	SourceRef   string
}

type tokenReceiptPayload struct {
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

type moneroInvoiceRecord struct {
	AccountID string
	Invoice   MoneroInvoiceResponse
}

func (s *Store) TokenAssets(ctx context.Context) ([]TokenAsset, error) {
	rows, err := s.db.QueryContext(ctx, `
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

func (s *Store) TokenBalance(ctx context.Context, accountID, assetID string) (int64, error) {
	var balance sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
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

func (s *Store) TokenAppBalance(ctx context.Context, accountID, assetID, appID string) (int64, error) {
	var balance sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
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

func (s *Store) TokenLedger(ctx context.Context, accountID, assetID string, since int64) ([]TokenReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2 AND ledger_seq>?3
ORDER BY ledger_seq`, accountID, assetID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenReceipt
	for rows.Next() {
		item, err := scanTokenReceipt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) TokenAppLedger(ctx context.Context, accountID, assetID, appID string, since int64) ([]TokenReceipt, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE account_id=?1 AND asset_id=?2 AND app_id=?3 AND ledger_seq>?4
ORDER BY ledger_seq`, accountID, assetID, appID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenReceipt
	for rows.Next() {
		item, err := scanTokenReceipt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) TokenReceipt(ctx context.Context, receiptID string) (TokenReceipt, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE receipt_id=?1`, receiptID)
	receipt, err := scanTokenReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenReceipt{}, false, nil
	}
	if err != nil {
		return TokenReceipt{}, false, err
	}
	return receipt, true, nil
}

type tokenReceiptScanner interface {
	Scan(dest ...any) error
}

func scanTokenReceipt(row tokenReceiptScanner) (TokenReceipt, error) {
	var item TokenReceipt
	err := row.Scan(&item.ReceiptID, &item.IssuerID, &item.AssetID, &item.AccountID,
		&item.AppID, &item.EventType, &item.AmountDelta, &item.LedgerSeq,
		&item.PreviousHash, &item.EventHash, &item.CreatedAt, &item.SourceType,
		&item.SourceRef, &item.Signature)
	return item, err
}

func (s *Store) CreditTokenPayment(ctx context.Context, signer ed25519.PrivateKey, provider, providerPaymentID string, input tokenEventInput) (TokenReceipt, bool, error) {
	if provider == "" || providerPaymentID == "" {
		return TokenReceipt{}, false, errors.New("provider payment id required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenReceipt{}, false, err
	}
	defer tx.Rollback()

	var existingReceiptID string
	err = tx.QueryRowContext(ctx, `
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
			return TokenReceipt{}, false, err
		}
		if existingAccountID != input.AccountID || existingAssetID != waoziTokenAssetID || existingAmount != input.AmountDelta {
			return TokenReceipt{}, false, errors.New("provider payment id collision")
		}
		receipt, found, err := tokenReceiptByIDTx(ctx, tx, existingReceiptID)
		if err != nil {
			return TokenReceipt{}, false, err
		}
		if !found {
			return TokenReceipt{}, false, errors.New("processed payment receipt missing")
		}
		return receipt, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return TokenReceipt{}, false, err
	}

	receipt, err := insertTokenEventTx(ctx, tx, signer, input)
	if err != nil {
		return TokenReceipt{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_processed_payments(provider,provider_payment_id,account_id,asset_id,amount,receipt_id)
VALUES(?1,?2,?3,?4,?5,?6)`, provider, providerPaymentID, input.AccountID,
		waoziTokenAssetID, input.AmountDelta, receipt.ReceiptID); err != nil {
		return TokenReceipt{}, false, err
	}
	return receipt, true, tx.Commit()
}

func (s *Store) SpendTokens(ctx context.Context, signer ed25519.PrivateKey, input tokenEventInput, idempotencyKey string) (TokenReceipt, int64, bool, error) {
	if input.AmountDelta >= 0 {
		return TokenReceipt{}, 0, false, errors.New("spend amount must be negative")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenReceipt{}, 0, false, err
	}
	defer tx.Rollback()

	var existingReceiptID string
	err = tx.QueryRowContext(ctx, `
SELECT receipt_id
FROM token_spend_nonces
WHERE account_id=?1 AND app_id=?2 AND idempotency_key=?3`,
		input.AccountID, input.AppID, idempotencyKey).Scan(&existingReceiptID)
	if err == nil {
		receipt, found, err := tokenReceiptByIDTx(ctx, tx, existingReceiptID)
		if err != nil {
			return TokenReceipt{}, 0, false, err
		}
		if !found {
			return TokenReceipt{}, 0, false, errors.New("spend receipt missing")
		}
		balance, err := tokenBalanceTx(ctx, tx, input.AccountID, waoziTokenAssetID)
		if err != nil {
			return TokenReceipt{}, 0, false, err
		}
		return receipt, balance, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return TokenReceipt{}, 0, false, err
	}

	balance, err := tokenBalanceTx(ctx, tx, input.AccountID, waoziTokenAssetID)
	if err != nil {
		return TokenReceipt{}, 0, false, err
	}
	if balance+input.AmountDelta < 0 {
		return TokenReceipt{}, balance, false, errors.New("insufficient balance")
	}
	receipt, err := insertTokenEventTx(ctx, tx, signer, input)
	if err != nil {
		return TokenReceipt{}, 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_spend_nonces(account_id,app_id,idempotency_key,receipt_id)
VALUES(?1,?2,?3,?4)`, input.AccountID, input.AppID, idempotencyKey, receipt.ReceiptID); err != nil {
		return TokenReceipt{}, 0, false, err
	}
	balance += input.AmountDelta
	return receipt, balance, true, tx.Commit()
}

func insertTokenEventTx(ctx context.Context, tx *sql.Tx, signer ed25519.PrivateKey, input tokenEventInput) (TokenReceipt, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return TokenReceipt{}, errTokenIssuerReadOnly
	}
	if err := validateTokenEventInput(input); err != nil {
		return TokenReceipt{}, err
	}
	var previousHash sql.NullString
	var previousSeq sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
SELECT ledger_seq,event_hash
FROM token_ledger
ORDER BY ledger_seq DESC
LIMIT 1`).Scan(&previousSeq, &previousHash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return TokenReceipt{}, err
	}
	ledgerSeq := int64(1)
	if previousSeq.Valid {
		ledgerSeq = previousSeq.Int64 + 1
	}
	receiptID, err := randomUkuID()
	if err != nil {
		return TokenReceipt{}, err
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	payload := tokenReceiptPayload{
		ReceiptID:    receiptID,
		IssuerID:     waoziIssuerID,
		AssetID:      waoziTokenAssetID,
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
	eventHash := hashTokenReceiptPayload(payload)
	payload.EventHash = eventHash
	signature := ed25519.Sign(signer, canonicalTokenReceiptPayload(payload))
	receipt := tokenReceiptFromPayload(payload, signature)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO token_ledger(receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,
	ledger_seq,previous_hash,event_hash,signature,created_at,source_type,source_ref)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)`,
		receipt.ReceiptID, receipt.IssuerID, receipt.AssetID, receipt.AccountID,
		receipt.AppID, receipt.EventType, receipt.AmountDelta, receipt.LedgerSeq,
		receipt.PreviousHash, receipt.EventHash, receipt.Signature, receipt.CreatedAt,
		receipt.SourceType, receipt.SourceRef); err != nil {
		return TokenReceipt{}, err
	}
	return receipt, nil
}

func validateTokenEventInput(input tokenEventInput) error {
	if !validUserID(input.AccountID) {
		return errors.New("invalid account_id")
	}
	if input.AppID != "" && !validNamespace(input.AppID) {
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
	if !validNamespace(input.SourceType) || strings.TrimSpace(input.SourceRef) == "" || len(input.SourceRef) > 256 {
		return errors.New("invalid source")
	}
	return nil
}

func tokenReceiptByIDTx(ctx context.Context, tx *sql.Tx, receiptID string) (TokenReceipt, bool, error) {
	row := tx.QueryRowContext(ctx, `
SELECT receipt_id,issuer_id,asset_id,account_id,app_id,event_type,amount_delta,ledger_seq,
	previous_hash,event_hash,created_at,source_type,source_ref,signature
FROM token_ledger
WHERE receipt_id=?1`, receiptID)
	receipt, err := scanTokenReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenReceipt{}, false, nil
	}
	if err != nil {
		return TokenReceipt{}, false, err
	}
	return receipt, true, nil
}

func tokenBalanceTx(ctx context.Context, tx *sql.Tx, accountID, assetID string) (int64, error) {
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

func tokenReceiptFromPayload(payload tokenReceiptPayload, signature []byte) TokenReceipt {
	return TokenReceipt{
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

func canonicalTokenReceiptPayload(payload tokenReceiptPayload) []byte {
	data, _ := json.Marshal(payload)
	return append([]byte(tokenReceiptContext+"\n"), data...)
}

func hashTokenReceiptPayload(payload tokenReceiptPayload) string {
	payload.EventHash = ""
	sum := sha256.Sum256(canonicalTokenReceiptPayload(payload))
	return hex.EncodeToString(sum[:])
}

func validTokenReceiptSignature(publicKey ed25519.PublicKey, receipt TokenReceipt) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload := tokenReceiptPayload{
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
	return receipt.EventHash == hashTokenReceiptPayload(payload) &&
		ed25519.Verify(publicKey, canonicalTokenReceiptPayload(payload), signature)
}

func (s *Server) tokenIssuerStatus() string {
	if len(s.cfg.WaoziIssuerPrivateKey) == ed25519.PrivateKeySize {
		return "ok"
	}
	if len(s.cfg.WaoziIssuerPublicKey) == ed25519.PublicKeySize {
		return "read_only"
	}
	return "disabled"
}

func (s *Server) requireTokenIssuer() (ed25519.PrivateKey, error) {
	if len(s.cfg.WaoziIssuerPrivateKey) != ed25519.PrivateKeySize {
		return nil, errTokenIssuerReadOnly
	}
	return s.cfg.WaoziIssuerPrivateKey, nil
}

func hasMoneroTokenProduct(products map[string]TokenProduct) bool {
	for _, product := range products {
		if product.TokenUnits > 0 && product.MoneroAtomicAmount > 0 {
			return true
		}
	}
	return false
}

func (s *Server) handleTokenAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.store.TokenAssets(r.Context())
	if err != nil {
		slog.Error("list token assets", "error", err)
		writeError(w, http.StatusInternalServerError, "token assets failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenAssetsResponse{Assets: assets})
}

func (s *Server) handleTokenProducts(w http.ResponseWriter, r *http.Request) {
	products := make([]TokenProduct, 0, len(s.cfg.TokenProducts))
	for _, product := range s.cfg.TokenProducts {
		if !s.cfg.TokenDirectPurchasesEnabled {
			product.MoneroAtomicAmount = 0
		}
		products = append(products, product)
	}
	sort.Slice(products, func(i, j int) bool {
		return products[i].ProductID < products[j].ProductID
	})
	writeJSON(w, http.StatusOK, TokenProductsResponse{Products: products})
}

func (s *Server) handleTokenIssuer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, TokenIssuerResponse{
		IssuerID:  waoziIssuerID,
		PublicKey: hex.EncodeToString(s.cfg.WaoziIssuerPublicKey),
		Algorithm: "Ed25519",
		Status:    s.tokenIssuerStatus(),
	})
}

func (s *Server) handleTokenBalance(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	appID, appScoped, err := tokenAppFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var balance int64
	if appScoped {
		balance, err = s.store.TokenAppBalance(r.Context(), userID, waoziTokenAssetID, appID)
	} else {
		balance, err = s.store.TokenBalance(r.Context(), userID, waoziTokenAssetID)
	}
	if err != nil {
		slog.Error("token balance", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenBalanceResponse{
		AccountID: userID,
		AssetID:   waoziTokenAssetID,
		AppID:     appID,
		Balance:   balance,
	})
}

func (s *Server) handleTokenLedger(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	since, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("since")), 10, 64)
	appID, appScoped, err := tokenAppFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var events []TokenReceipt
	if appScoped {
		events, err = s.store.TokenAppLedger(r.Context(), userID, waoziTokenAssetID, appID, since)
	} else {
		events, err = s.store.TokenLedger(r.Context(), userID, waoziTokenAssetID, since)
	}
	if err != nil {
		slog.Error("token ledger", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "token ledger failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenLedgerResponse{Events: events})
}

func (s *Server) handleTokenReceipt(w http.ResponseWriter, r *http.Request) {
	receiptID := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/receipts/")
	if !validUkuID(receiptID) {
		writeError(w, http.StatusBadRequest, "invalid receipt_id")
		return
	}
	receipt, found, err := s.store.TokenReceipt(r.Context(), receiptID)
	if err != nil {
		slog.Error("token receipt", "receipt", logText(receiptID), "error", err)
		writeError(w, http.StatusInternalServerError, "token receipt failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "receipt not found")
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) handleTokenSpend(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := readTokenSpendRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	signer, err := s.requireTokenIssuer()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	if req.AssetID != waoziTokenAssetID {
		writeError(w, http.StatusBadRequest, "unsupported asset_id")
		return
	}
	if exists, err := s.store.AppExists(r.Context(), req.AppID); err != nil {
		slog.Error("token spend app lookup", "app", logText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "token spend failed")
		return
	} else if !exists {
		writeError(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	if err := s.authorizeTokenApp(r.Context(), r, body, userID, req.AppID, req.AssetID, tokenPermissionSpend); err != nil {
		s.writeAuthError(w, err)
		return
	}
	sourceRef := req.Action + ":" + req.IdempotencyKey
	if req.Metadata != "" {
		sourceRef += ":" + shortHash(req.Metadata)
	}
	receipt, balance, _, err := s.store.SpendTokens(r.Context(), signer, tokenEventInput{
		AccountID:   userID,
		AppID:       req.AppID,
		EventType:   "debit",
		AmountDelta: -req.Amount,
		SourceType:  "spend",
		SourceRef:   sourceRef,
	}, req.IdempotencyKey)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient balance") {
			writeError(w, http.StatusConflict, "insufficient balance")
			return
		}
		slog.Error("token spend", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "token spend failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenSpendResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func (s *Server) handleGooglePurchaseVerify(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := readGooglePurchaseVerifyRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	signer, err := s.requireTokenIssuer()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	product, ok := s.cfg.TokenProducts[req.ProductID]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown product_id")
		return
	}
	if exists, err := s.store.AppExists(r.Context(), req.AppID); err != nil {
		slog.Error("google token purchase app lookup", "app", logText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "token purchase failed")
		return
	} else if !exists {
		writeError(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	if err := s.authorizeTokenApp(r.Context(), r, body, userID, req.AppID, waoziTokenAssetID, tokenPermissionPurchase); err != nil {
		s.writeAuthError(w, err)
		return
	}
	if len(s.cfg.GooglePackageNames) > 0 && !s.cfg.GooglePackageNames[req.PackageName] {
		writeError(w, http.StatusBadRequest, "package not allowed")
		return
	}
	paymentID, err := verifyGooglePlayPurchase(r.Context(), s.cfg, req)
	if err != nil {
		writePaymentError(w, err)
		return
	}
	receipt, _, err := s.store.CreditTokenPayment(r.Context(), signer, "google_play", paymentID, tokenEventInput{
		AccountID:   userID,
		AppID:       req.AppID,
		EventType:   "credit",
		AmountDelta: product.TokenUnits,
		SourceType:  "google_play",
		SourceRef:   paymentID,
	})
	if err != nil {
		slog.Error("google token credit", "user", logText(userID), "payment", logText(paymentID), "error", err)
		writeError(w, http.StatusInternalServerError, "token credit failed")
		return
	}
	if err := consumeGooglePlayPurchase(r.Context(), s.cfg, req); err != nil {
		slog.Warn("google purchase consume failed after token credit", "user", logText(userID), "payment", logText(paymentID), "error", err)
	}
	balance, err := s.store.TokenBalance(r.Context(), userID, waoziTokenAssetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenPurchaseResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func (s *Server) handleMoneroInvoices(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := readMoneroInvoiceRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.cfg.TokenDirectPurchasesEnabled {
		writeError(w, http.StatusServiceUnavailable, "direct token purchases disabled")
		return
	}
	product, ok := s.cfg.TokenProducts[req.ProductID]
	if !ok || product.MoneroAtomicAmount <= 0 {
		writeError(w, http.StatusBadRequest, "unknown monero product_id")
		return
	}
	if exists, err := s.store.AppExists(r.Context(), req.AppID); err != nil {
		slog.Error("monero invoice app lookup", "app", logText(req.AppID), "error", err)
		writeError(w, http.StatusInternalServerError, "monero invoice failed")
		return
	} else if !exists {
		writeError(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	if err := s.authorizeTokenApp(r.Context(), r, body, userID, req.AppID, waoziTokenAssetID, tokenPermissionPurchase); err != nil {
		s.writeAuthError(w, err)
		return
	}
	invoice, err := s.store.CreateMoneroInvoice(r.Context(), userID, req.AppID, product, s.cfg)
	if err != nil {
		slog.Error("create monero invoice", "user", logText(userID), "error", err)
		writeError(w, http.StatusInternalServerError, "monero invoice failed")
		return
	}
	writeJSON(w, http.StatusCreated, invoice)
}

func (s *Server) handleMoneroInvoiceRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/purchases/monero/invoices/")
	if !validUkuID(id) {
		writeError(w, http.StatusBadRequest, "invalid invoice id")
		return
	}
	invoice, found, err := s.store.MoneroInvoice(r.Context(), userID, id)
	if err != nil {
		slog.Error("load monero invoice", "user", logText(userID), "invoice", logText(id), "error", err)
		writeError(w, http.StatusInternalServerError, "monero invoice failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "invoice not found")
		return
	}
	if invoice.Status == "pending" {
		if updated, err := s.trySettleOrExpireMoneroInvoice(r.Context(), userID, invoice); err != nil {
			slog.Warn("monero invoice settlement failed", "user", logText(userID), "invoice", logText(id), "error", err)
		} else if updated.ID != "" {
			invoice = updated
		}
	}
	writeJSON(w, http.StatusOK, invoice)
}

func (s *Server) trySettleOrExpireMoneroInvoice(ctx context.Context, userID string, invoice MoneroInvoiceResponse) (MoneroInvoiceResponse, error) {
	signer, err := s.requireTokenIssuer()
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	paymentID, seen, confirmed, err := verifyMoneroInvoicePayment(ctx, s.cfg, invoice)
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	if !confirmed {
		if !seen && moneroInvoiceExpired(invoice) {
			if err := s.store.MarkMoneroInvoiceExpired(ctx, userID, invoice.ID); err != nil {
				return MoneroInvoiceResponse{}, err
			}
			updated, _, err := s.store.MoneroInvoice(ctx, userID, invoice.ID)
			return updated, err
		}
		return MoneroInvoiceResponse{}, nil
	}
	receipt, _, err := s.store.CreditTokenPayment(ctx, signer, "monero", paymentID, tokenEventInput{
		AccountID:   userID,
		AppID:       invoice.AppID,
		EventType:   "credit",
		AmountDelta: invoice.TokenUnits,
		SourceType:  "monero",
		SourceRef:   paymentID,
	})
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	if err := s.store.MarkMoneroInvoicePaid(ctx, userID, invoice.ID, receipt.ReceiptID, paymentID); err != nil {
		return MoneroInvoiceResponse{}, err
	}
	updated, _, err := s.store.MoneroInvoice(ctx, userID, invoice.ID)
	return updated, err
}

func moneroInvoiceExpired(invoice MoneroInvoiceResponse) bool {
	expiresAt, err := time.Parse(time.RFC3339, invoice.ExpiresAt)
	return err == nil && time.Now().UTC().After(expiresAt)
}

func (s *Server) runMoneroInvoiceReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.reconcileMoneroInvoices(ctx, 100); err != nil {
			slog.Warn("monero invoice reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) reconcileMoneroInvoices(ctx context.Context, limit int) error {
	invoices, err := s.store.PendingMoneroInvoices(ctx, limit)
	if err != nil {
		return err
	}
	for _, item := range invoices {
		if _, err := s.trySettleOrExpireMoneroInvoice(ctx, item.AccountID, item.Invoice); err != nil {
			slog.Warn("monero invoice reconciliation item failed", "account", logText(item.AccountID),
				"invoice", logText(item.Invoice.ID), "error", err)
		}
	}
	return nil
}

func (s *Server) handleTokenCheckpointLatest(w http.ResponseWriter, r *http.Request) {
	checkpoint, found, err := s.store.LatestTokenCheckpoint(r.Context())
	if err != nil {
		slog.Error("token checkpoint", "error", err)
		writeError(w, http.StatusInternalServerError, "token checkpoint failed")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "checkpoint not found")
		return
	}
	writeJSON(w, http.StatusOK, checkpoint)
}

func (s *Server) handleAdminManualCredit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		AppID     string `json:"app_id"`
		Amount    int64  `json:"amount"`
		SourceRef string `json:"source_ref"`
	}
	body, err := readJSONBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.AccountID = strings.ToLower(strings.TrimSpace(req.AccountID))
	req.AppID = strings.TrimSpace(req.AppID)
	req.SourceRef = strings.TrimSpace(req.SourceRef)
	signer, err := s.requireTokenIssuer()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	if req.SourceRef == "" {
		req.SourceRef = "manual:" + time.Now().UTC().Format(time.RFC3339Nano)
	}
	receipt, _, err := s.store.CreditTokenPayment(r.Context(), signer, "admin", req.SourceRef, tokenEventInput{
		AccountID:   req.AccountID,
		AppID:       req.AppID,
		EventType:   "credit",
		AmountDelta: req.Amount,
		SourceType:  "admin",
		SourceRef:   req.SourceRef,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	balance, err := s.store.TokenBalance(r.Context(), req.AccountID, waoziTokenAssetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	writeJSON(w, http.StatusOK, TokenPurchaseResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func (s *Server) handleAdminTokenCheckpoint(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	signer, err := s.requireTokenIssuer()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	checkpoint, err := s.store.CreateTokenCheckpoint(r.Context(), signer)
	if err != nil {
		slog.Error("create token checkpoint", "error", err)
		writeError(w, http.StatusInternalServerError, "token checkpoint failed")
		return
	}
	writeJSON(w, http.StatusOK, checkpoint)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		writeError(w, http.StatusForbidden, "admin disabled")
		return false
	}
	if requestHeaderAlias(r, "X-Daochi-Admin", "X-Ksync-Admin") != s.cfg.AdminToken {
		writeError(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func readTokenSpendRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (TokenSpendRequest, []byte, error) {
	var req TokenSpendRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, nil, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.AssetID = strings.TrimSpace(req.AssetID)
	req.Action = strings.TrimSpace(req.Action)
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	req.Metadata = strings.TrimSpace(req.Metadata)
	if !validNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.AssetID == "" {
		req.AssetID = waoziTokenAssetID
	}
	if req.Amount <= 0 {
		return req, nil, errors.New("amount required")
	}
	if !validNamespace(req.Action) {
		return req, nil, errors.New("invalid action")
	}
	if !validClientID(req.IdempotencyKey) {
		return req, nil, errors.New("invalid idempotency_key")
	}
	return req, body, nil
}

func readGooglePurchaseVerifyRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (GooglePurchaseVerifyRequest, []byte, error) {
	var req GooglePurchaseVerifyRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, nil, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.PackageName = strings.TrimSpace(req.PackageName)
	req.ProductID = strings.TrimSpace(req.ProductID)
	req.PurchaseToken = strings.TrimSpace(req.PurchaseToken)
	if !validNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.PackageName == "" || req.ProductID == "" || req.PurchaseToken == "" {
		return req, nil, errors.New("purchase fields required")
	}
	return req, body, nil
}

func readMoneroInvoiceRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (MoneroInvoiceRequest, []byte, error) {
	var req MoneroInvoiceRequest
	body, err := readJSONBody(w, r, maxBody)
	if err != nil {
		return req, nil, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.ProductID = strings.TrimSpace(req.ProductID)
	if !validNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.ProductID == "" {
		return req, nil, errors.New("product_id required")
	}
	return req, body, nil
}

func tokenAppFilter(r *http.Request) (string, bool, error) {
	appID := strings.TrimSpace(r.URL.Query().Get("app_id"))
	if appID == "" {
		return "", false, nil
	}
	if !validNamespace(appID) {
		return "", false, errors.New("invalid app_id")
	}
	return appID, true, nil
}

func (s *Server) authorizeTokenApp(ctx context.Context, r *http.Request, body []byte, accountID, appID, assetID, permission string) error {
	hasSignedTx := strings.TrimSpace(r.Header.Get("X-Daochi-Tx")) != ""
	if hasSignedTx {
		tx, err := readSignedTxHeader(r)
		if err != nil {
			return err
		}
		if err := s.verifySignedTx(ctx, r, body, tx, accountID, appID); err != nil {
			return err
		}
	}
	if !validTokenPolicyPermission(permission) {
		return authError{status: http.StatusBadRequest, message: "invalid token permission"}
	}
	hasPolicy, err := s.store.HasTokenPolicy(ctx, appID)
	if err != nil {
		return err
	}
	if !hasPolicy {
		return nil
	}
	_, ok, err := s.store.AppTokenPermission(ctx, appID, assetID, permission)
	if err != nil {
		return err
	}
	if !ok {
		return authError{status: http.StatusForbidden, message: "app token permission denied"}
	}
	return nil
}

func validTokenPolicyPermission(value string) bool {
	switch value {
	case tokenPermissionSpend, tokenPermissionPurchase:
		return true
	default:
		return false
	}
}

func writePaymentError(w http.ResponseWriter, err error) {
	if errors.Is(err, errPaymentUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "payment verifier unavailable")
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func verifyGooglePlayPurchase(ctx context.Context, cfg Config, req GooglePurchaseVerifyRequest) (string, error) {
	if !cfg.hasGooglePlayVerifier() {
		return "", errPaymentUnavailable
	}
	accessToken, err := googleAccessToken(ctx, cfg)
	if err != nil {
		return "", errPaymentUnavailable
	}
	endpoint := "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/" +
		url.PathEscape(req.PackageName) + "/purchases/products/" +
		url.PathEscape(req.ProductID) + "/tokens/" + url.PathEscape(req.PurchaseToken)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", errPaymentUnavailable
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("google purchase rejected")
	}
	var payload struct {
		PurchaseState        int    `json:"purchaseState"`
		ConsumptionState     int    `json:"consumptionState"`
		AcknowledgementState int    `json:"acknowledgementState"`
		OrderID              string `json:"orderId"`
		PurchaseType         *int   `json:"purchaseType,omitempty"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", errors.New("invalid google purchase response")
	}
	if payload.PurchaseState != 0 {
		return "", errors.New("google purchase is not purchased")
	}
	if payload.ConsumptionState == 1 {
		return "", errors.New("google purchase already consumed")
	}
	ref := payload.OrderID
	if ref == "" {
		ref = shortHash(req.PurchaseToken)
	}
	return req.PackageName + ":" + req.ProductID + ":" + ref, nil
}

func consumeGooglePlayPurchase(ctx context.Context, cfg Config, req GooglePurchaseVerifyRequest) error {
	if !cfg.hasGooglePlayVerifier() {
		return errPaymentUnavailable
	}
	accessToken, err := googleAccessToken(ctx, cfg)
	if err != nil {
		return err
	}
	endpoint := "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/" +
		url.PathEscape(req.PackageName) + "/purchases/products/" +
		url.PathEscape(req.ProductID) + "/tokens/" + url.PathEscape(req.PurchaseToken) + ":consume"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("google consume status %d", res.StatusCode)
	}
	return nil
}

type googleServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type googleOAuthClientFile struct {
	Web       googleOAuthClient `json:"web"`
	Installed googleOAuthClient `json:"installed"`
}

type googleOAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURI     string   `json:"token_uri"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (cfg Config) hasGooglePlayVerifier() bool {
	return cfg.GoogleServiceAccountJSON != "" ||
		(cfg.GoogleOAuthClientJSON != "" && cfg.GoogleOAuthRefreshToken != "")
}

func googleAccessToken(ctx context.Context, cfg Config) (string, error) {
	if cfg.GoogleServiceAccountJSON != "" {
		return googleServiceAccountAccessToken(ctx, cfg.GoogleServiceAccountJSON)
	}
	return googleRefreshAccessToken(ctx, cfg.GoogleOAuthClientJSON, cfg.GoogleOAuthRefreshToken)
}

func googleServiceAccountAccessToken(ctx context.Context, raw string) (string, error) {
	var account googleServiceAccount
	if err := json.Unmarshal([]byte(raw), &account); err != nil {
		return "", err
	}
	if account.TokenURI == "" {
		account.TokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return "", errors.New("invalid google private key")
	}
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("google private key must be rsa")
	}
	now := time.Now().Unix()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iss":   account.ClientEmail,
		"scope": "https://www.googleapis.com/auth/androidpublisher",
		"aud":   account.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	}
	segments := []string{base64URLJSON(header), base64URLJSON(claims)}
	signed := strings.Join(segments, ".")
	hash := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	assertion := signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", errors.New("google oauth rejected")
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("google oauth missing access token")
	}
	return payload.AccessToken, nil
}

func googleRefreshAccessToken(ctx context.Context, rawClient, refreshToken string) (string, error) {
	var file googleOAuthClientFile
	if err := json.Unmarshal([]byte(rawClient), &file); err != nil {
		return "", err
	}
	client := file.Web
	if client.ClientID == "" {
		client = file.Installed
	}
	if client.ClientID == "" || client.ClientSecret == "" {
		return "", errors.New("invalid google oauth client")
	}
	if client.TokenURI == "" {
		client.TokenURI = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientID},
		"client_secret": {client.ClientSecret},
		"refresh_token": {strings.TrimSpace(refreshToken)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", errors.New("google oauth refresh rejected")
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("google oauth missing access token")
	}
	return payload.AccessToken, nil
}

func base64URLJSON(value any) string {
	data, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *Store) CreateMoneroInvoice(ctx context.Context, accountID, appID string, product TokenProduct, cfg Config) (MoneroInvoiceResponse, error) {
	if product.MoneroAtomicAmount <= 0 {
		return MoneroInvoiceResponse{}, errors.New("monero amount required")
	}
	id, err := randomUkuID()
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	address, index, err := createMoneroSubaddress(ctx, cfg, "daochi-"+id)
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	expiresAt := time.Now().UTC().Add(45 * time.Minute).Format(time.RFC3339)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO token_payment_intents(id,provider,account_id,app_id,product_id,asset_id,token_units,
	provider_amount,provider_address,provider_ref,status,expires_at)
VALUES(?1,'monero',?2,?3,?4,?5,?6,?7,?8,?9,'pending',?10)`,
		id, accountID, appID, product.ProductID, waoziTokenAssetID, product.TokenUnits,
		product.MoneroAtomicAmount, address, strconv.Itoa(index), expiresAt)
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	return MoneroInvoiceResponse{
		ID:           id,
		AppID:        appID,
		Status:       "pending",
		ProductID:    product.ProductID,
		AssetID:      waoziTokenAssetID,
		TokenUnits:   product.TokenUnits,
		AtomicAmount: product.MoneroAtomicAmount,
		Address:      address,
		AddressIndex: index,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Store) MoneroInvoice(ctx context.Context, accountID, id string) (MoneroInvoiceResponse, bool, error) {
	var out MoneroInvoiceResponse
	var receiptID string
	err := s.db.QueryRowContext(ctx, `
SELECT id,app_id,status,product_id,asset_id,token_units,provider_amount,provider_address,provider_ref,provider_payment_id,expires_at,receipt_id
FROM token_payment_intents
WHERE account_id=?1 AND id=?2 AND provider='monero'`, accountID, id).Scan(
		&out.ID, &out.AppID, &out.Status, &out.ProductID, &out.AssetID, &out.TokenUnits,
		&out.AtomicAmount, &out.Address, &out.AddressIndex, &out.PaymentID, &out.ExpiresAt, &receiptID)
	if errors.Is(err, sql.ErrNoRows) {
		return MoneroInvoiceResponse{}, false, nil
	}
	if err != nil {
		return MoneroInvoiceResponse{}, false, err
	}
	if receiptID != "" {
		receipt, found, err := s.TokenReceipt(ctx, receiptID)
		if err != nil {
			return MoneroInvoiceResponse{}, false, err
		}
		if found {
			out.Receipt = &receipt
		}
	}
	return out, true, nil
}

func (s *Store) PendingMoneroInvoices(ctx context.Context, limit int) ([]moneroInvoiceRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT account_id,id,app_id,status,product_id,asset_id,token_units,provider_amount,
	provider_address,provider_ref,provider_payment_id,expires_at,receipt_id
FROM token_payment_intents
WHERE provider='monero' AND status='pending'
ORDER BY created_at
LIMIT ?1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []moneroInvoiceRecord{}
	for rows.Next() {
		var item moneroInvoiceRecord
		var receiptID string
		if err := rows.Scan(&item.AccountID, &item.Invoice.ID, &item.Invoice.AppID,
			&item.Invoice.Status, &item.Invoice.ProductID, &item.Invoice.AssetID,
			&item.Invoice.TokenUnits, &item.Invoice.AtomicAmount, &item.Invoice.Address,
			&item.Invoice.AddressIndex, &item.Invoice.PaymentID, &item.Invoice.ExpiresAt,
			&receiptID); err != nil {
			return nil, err
		}
		if receiptID != "" {
			receipt, found, err := s.TokenReceipt(ctx, receiptID)
			if err != nil {
				return nil, err
			}
			if found {
				item.Invoice.Receipt = &receipt
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) MarkMoneroInvoicePaid(ctx context.Context, accountID, id, receiptID, paymentRef string) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE token_payment_intents
SET status='paid', receipt_id=?3, provider_payment_id=?4, updated_at=CURRENT_TIMESTAMP
WHERE account_id=?1 AND id=?2 AND provider='monero' AND status='pending'`,
		accountID, id, receiptID, paymentRef)
	if err != nil {
		return err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("invoice not pending")
	}
	return nil
}

func (s *Store) MarkMoneroInvoiceExpired(ctx context.Context, accountID, id string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE token_payment_intents
SET status='expired', updated_at=CURRENT_TIMESTAMP
WHERE account_id=?1 AND id=?2 AND provider='monero' AND status='pending'`,
		accountID, id)
	return err
}

func createMoneroSubaddress(ctx context.Context, cfg Config, label string) (string, int, error) {
	if cfg.MoneroWalletRPCURL == "" {
		return "", 0, errPaymentUnavailable
	}
	var result struct {
		Address      string `json:"address"`
		AddressIndex int    `json:"address_index"`
	}
	if err := moneroRPC(ctx, cfg, "create_address", map[string]any{
		"account_index": 0,
		"label":         label,
	}, &result); err != nil {
		return "", 0, err
	}
	if result.Address == "" {
		return "", 0, errors.New("monero rpc missing address")
	}
	return result.Address, result.AddressIndex, nil
}

func verifyMoneroInvoicePayment(ctx context.Context, cfg Config, invoice MoneroInvoiceResponse) (string, bool, bool, error) {
	if cfg.MoneroWalletRPCURL == "" {
		return "", false, false, errPaymentUnavailable
	}
	var result struct {
		In []struct {
			TxID          string `json:"txid"`
			Amount        int64  `json:"amount"`
			Confirmations int64  `json:"confirmations"`
			SubaddrIndex  struct {
				Major int `json:"major"`
				Minor int `json:"minor"`
			} `json:"subaddr_index"`
		} `json:"in"`
	}
	if err := moneroRPC(ctx, cfg, "get_transfers", map[string]any{
		"in":              true,
		"pending":         true,
		"pool":            true,
		"failed":          false,
		"account_index":   0,
		"subaddr_indices": []int{invoice.AddressIndex},
	}, &result); err != nil {
		return "", false, false, err
	}
	for _, tx := range result.In {
		if tx.Amount >= invoice.AtomicAmount &&
			tx.SubaddrIndex.Major == 0 && tx.SubaddrIndex.Minor == invoice.AddressIndex && tx.TxID != "" {
			paymentID := fmt.Sprintf("%s:%d:%d", tx.TxID, tx.SubaddrIndex.Major, tx.SubaddrIndex.Minor)
			return paymentID, true, tx.Confirmations >= 10, nil
		}
	}
	return "", false, false, nil
}

func moneroRPC(ctx context.Context, cfg Config, method string, params map[string]any, out any) error {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "0",
		"method":  method,
		"params":  params,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.MoneroWalletRPCURL+"/json_rpc", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.MoneroWalletRPCUser != "" || cfg.MoneroWalletRPCPassword != "" {
		req.SetBasicAuth(cfg.MoneroWalletRPCUser, cfg.MoneroWalletRPCPassword)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return errPaymentUnavailable
	}
	defer res.Body.Close()
	response, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("monero rpc status %d", res.StatusCode)
	}
	var wrapper struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response, &wrapper); err != nil {
		return err
	}
	if wrapper.Error != nil {
		return fmt.Errorf("monero rpc error: %s", wrapper.Error.Message)
	}
	return json.Unmarshal(wrapper.Result, out)
}

func (s *Store) CreateTokenCheckpoint(ctx context.Context, signer ed25519.PrivateKey) (TokenCheckpoint, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return TokenCheckpoint{}, errTokenIssuerReadOnly
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ledger_seq,event_hash
FROM token_ledger
WHERE issuer_id=?1 AND asset_id=?2
ORDER BY ledger_seq`, waoziIssuerID, waoziTokenAssetID)
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
		waoziIssuerID, waoziTokenAssetID, seq, ledgerRoot))
	signature := hex.EncodeToString(ed25519.Sign(signer, message))
	_, err = s.db.ExecContext(ctx, `
INSERT INTO token_checkpoints(ledger_seq,issuer_id,asset_id,ledger_root,signature)
VALUES(?1,?2,?3,?4,?5)
ON CONFLICT(ledger_seq) DO UPDATE SET
	ledger_root=excluded.ledger_root,
	signature=excluded.signature,
	created_at=CURRENT_TIMESTAMP`, seq, waoziIssuerID, waoziTokenAssetID, ledgerRoot, signature)
	if err != nil {
		return TokenCheckpoint{}, err
	}
	checkpoint, found, err := s.LatestTokenCheckpoint(ctx)
	if err != nil || !found {
		return TokenCheckpoint{}, err
	}
	return checkpoint, nil
}

func (s *Store) LatestTokenCheckpoint(ctx context.Context) (TokenCheckpoint, bool, error) {
	var out TokenCheckpoint
	err := s.db.QueryRowContext(ctx, `
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
