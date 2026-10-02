// Original Go invoice implementation retained only as a migration oracle.
package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type baselineInvoiceMoneroInvoiceRecord struct {
	AccountID string
	Invoice   MoneroInvoiceResponse
}

func (s *Server) baselineInvoiceHandleMoneroInvoices(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	decoded := PaymentRequest_ReadInvoice(w, r, s.cfg.MaxBodyBytes)
	req, body, err := decoded.Value, decoded.Body, decoded.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.cfg.TokenDirectPurchasesEnabled {
		Response_Error(w, http.StatusServiceUnavailable, "direct token purchases disabled")
		return
	}
	product, ok := s.cfg.TokenProducts[req.ProductID]
	if !ok || product.MoneroAtomicAmount <= 0 {
		Response_Error(w, http.StatusBadRequest, "unknown monero product_id")
		return
	}
	existence := AppStore_Exists(s.store.Database, r.Context(), req.AppID)
	if exists, err := existence.Value, existence.Error; err != nil {
		slog.Error("monero invoice app lookup", "app", LogSafety_LogText(req.AppID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "monero invoice failed")
		return
	} else if !exists {
		Response_Error(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	authorization := TokenPolicy_Authorize(s.store.Database, r.Context(), r, body, userID, req.AppID, AssetID, "purchase", s.verifier.Verify, errSignedTxReplay)
	signedTx, hasSignedTx, err := authorization.Value, authorization.Signed, baselineAuthenticationError(authorization.Authentication)
	if err != nil {
		if hasSignedTx {
			SignedTx_Forget(s.store.Database, r.Context(), signedTx)
		}
		s.baselineWriteAuthError(w, err)
		return
	}
	completed := false
	defer func() {
		if hasSignedTx && !completed {
			SignedTx_Forget(s.store.Database, r.Context(), signedTx)
		}
	}()
	invoice, err := s.store.baselineInvoiceCreateMoneroInvoice(r.Context(), userID, req.AppID, product, s.cfg)
	if err != nil {
		slog.Error("create monero invoice", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "monero invoice failed")
		return
	}
	completed = true
	Response_JSON(w, http.StatusCreated, invoice)
}

func (s *Server) baselineInvoiceHandleMoneroInvoiceRoute(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.baselineBearerUser(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/purchases/monero/invoices/")
	if !Identity_ValidResourceID(id) {
		Response_Error(w, http.StatusBadRequest, "invalid invoice id")
		return
	}
	invoice, found, err := s.store.baselineInvoiceMoneroInvoice(r.Context(), userID, id)
	if err != nil {
		slog.Error("load monero invoice", "user", LogSafety_LogText(userID), "invoice", LogSafety_LogText(id), "error", err)
		Response_Error(w, http.StatusInternalServerError, "monero invoice failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "invoice not found")
		return
	}
	if invoice.Status == "pending" {
		if updated, err := s.baselineInvoiceTrySettleOrExpireMoneroInvoice(r.Context(), userID, invoice); err != nil {
			slog.Warn("monero invoice settlement failed", "user", LogSafety_LogText(userID), "invoice", LogSafety_LogText(id), "error", err)
		} else if updated.ID != "" {
			invoice = updated
		}
	}
	Response_JSON(w, http.StatusOK, invoice)
}

func (s *Server) baselineInvoiceTrySettleOrExpireMoneroInvoice(ctx context.Context, userID string, invoice MoneroInvoiceResponse) (MoneroInvoiceResponse, error) {
	issuer := TokenPolicy_Issuer(s.cfg, errTokenIssuerReadOnly)
	signer, err := issuer.Value, issuer.Error
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	inspected := MoneroWallet_InspectInvoice(ctx, s.cfg, invoice, errPaymentUnavailable)
	payment, err := inspected.Value, inspected.Error
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	// A fully-covered invoice settles even after expiry: funds arriving
	// late must never disappear into an expired row.
	if payment.ConfirmedAtomic >= invoice.AtomicAmount {
		paymentResult := TokenLedger_CreditPayment(s.store.Database, ctx, signer, "monero", payment.PaymentID, TokenEventInput{
			AccountID:   userID,
			AppID:       invoice.AppID,
			EventType:   "credit",
			AmountDelta: invoice.TokenUnits,
			SourceType:  "monero",
			SourceRef:   payment.PaymentID,
		}, errTokenIssuerReadOnly)
		receipt, _, err := paymentResult.Value, paymentResult.Created, paymentResult.Error
		if err != nil {
			return MoneroInvoiceResponse{}, err
		}
		if err := s.store.baselineInvoiceMarkMoneroInvoicePaid(ctx, userID, invoice.ID, receipt.ReceiptID, payment.PaymentID); err != nil {
			return MoneroInvoiceResponse{}, err
		}
		updated, _, err := s.store.baselineInvoiceMoneroInvoice(ctx, userID, invoice.ID)
		return updated, err
	}
	if baselineInvoiceMoneroInvoiceExpired(invoice) {
		if err := s.store.baselineInvoiceMarkMoneroInvoiceExpired(ctx, userID, invoice.ID); err != nil {
			return MoneroInvoiceResponse{}, err
		}
		updated, _, err := s.store.baselineInvoiceMoneroInvoice(ctx, userID, invoice.ID)
		return updated, err
	}
	return MoneroInvoiceResponse{}, nil
}

// baselineInvoiceReconcileMoneroExpiredInvoices sweeps invoices that expired unpaid:
// late full payments are still credited at the invoice's rate, and
// partial funds are reported once per invoice as stuck for manual
// disposition (a view-only wallet cannot refund them automatically).
func (s *Server) baselineInvoiceReconcileMoneroExpiredInvoices(ctx context.Context, limit int) error {
	if strings.TrimSpace(s.cfg.MoneroWalletRPCURL) == "" {
		return nil
	}
	invoices, err := s.store.baselineInvoiceExpiredMoneroInvoices(ctx, limit)
	if err != nil {
		return err
	}
	if len(invoices) == 0 {
		return nil
	}
	issuer := TokenPolicy_Issuer(s.cfg, errTokenIssuerReadOnly)
	signer, err := issuer.Value, issuer.Error
	if err != nil {
		return err
	}
	for _, item := range invoices {
		inspected := MoneroWallet_InspectInvoice(ctx, s.cfg, item.Invoice, errPaymentUnavailable)
		payment, err := inspected.Value, inspected.Error
		if err != nil {
			slog.Warn("expired monero invoice sweep failed", "invoice", LogSafety_LogText(item.Invoice.ID), "error", err)
			continue
		}
		if payment.ConfirmedAtomic >= item.Invoice.AtomicAmount {
			paymentResult := TokenLedger_CreditPayment(s.store.Database, ctx, signer, "monero", payment.PaymentID, TokenEventInput{
				AccountID:   item.AccountID,
				AppID:       item.Invoice.AppID,
				EventType:   "credit",
				AmountDelta: item.Invoice.TokenUnits,
				SourceType:  "monero",
				SourceRef:   payment.PaymentID,
			}, errTokenIssuerReadOnly)
			receipt, _, err := paymentResult.Value, paymentResult.Created, paymentResult.Error
			if err != nil {
				slog.Warn("expired monero invoice credit failed", "invoice", LogSafety_LogText(item.Invoice.ID), "error", err)
				continue
			}
			if err := s.store.baselineInvoiceSettleExpiredMoneroInvoice(ctx, item.AccountID, item.Invoice.ID, receipt.ReceiptID, payment.PaymentID); err != nil {
				slog.Warn("expired monero invoice settle failed", "invoice", LogSafety_LogText(item.Invoice.ID), "error", err)
				continue
			}
			slog.Info("credited late monero invoice payment", "invoice", LogSafety_LogText(item.Invoice.ID),
				"account", LogSafety_LogText(item.AccountID), "payment", LogSafety_LogText(payment.PaymentID))
			continue
		}
		if payment.SeenAtomic > 0 {
			s.baselineInvoiceReportStuckMoneroInvoice(item.Invoice.ID, item.AccountID, payment)
		}
	}
	return nil
}

func (s *Server) baselineInvoiceReportStuckMoneroInvoice(invoiceID, accountID string, payment InvoicePaymentState) {
	if _, already := s.moneroStuckNotified.LoadOrStore(invoiceID, true); already {
		return
	}
	s.metrics.MoneroStuckInvoices.Add(1)
	slog.Warn("monero invoice has uncredited funds", "invoice", LogSafety_LogText(invoiceID),
		"account", LogSafety_LogText(accountID), "seen_atomic", payment.SeenAtomic,
		"confirmed_atomic", payment.ConfirmedAtomic)
}

func baselineInvoiceMoneroInvoiceExpired(invoice MoneroInvoiceResponse) bool {
	expiresAt, err := time.Parse(time.RFC3339, invoice.ExpiresAt)
	return err == nil && time.Now().UTC().After(expiresAt)
}

func (s *Server) baselineInvoiceRunMoneroInvoiceReconciler(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.baselineInvoiceReconcileMoneroInvoices(ctx, 100); err != nil {
			slog.Warn("monero invoice reconciliation failed", "error", err)
		}
		if err := s.baselineInvoiceReconcileMoneroExpiredInvoices(ctx, 50); err != nil {
			slog.Warn("monero expired invoice sweep failed", "error", err)
		}
		if err := MoneroDeposits_Reconcile(s.monero(), ctx); err != nil {
			slog.Warn("monero account deposit reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) baselineInvoiceReconcileMoneroInvoices(ctx context.Context, limit int) error {
	invoices, err := s.store.baselineInvoicePendingMoneroInvoices(ctx, limit)
	if err != nil {
		return err
	}
	for _, item := range invoices {
		if _, err := s.baselineInvoiceTrySettleOrExpireMoneroInvoice(ctx, item.AccountID, item.Invoice); err != nil {
			slog.Warn("monero invoice reconciliation item failed", "account", LogSafety_LogText(item.AccountID),
				"invoice", LogSafety_LogText(item.Invoice.ID), "error", err)
		}
	}
	return nil
}

func (s *Store) baselineInvoiceCreateMoneroInvoice(ctx context.Context, accountID, appID string, product TokenProduct, cfg Config) (MoneroInvoiceResponse, error) {
	if product.MoneroAtomicAmount <= 0 {
		return MoneroInvoiceResponse{}, errors.New("monero amount required")
	}
	resource := ResourceId_New()
	id, err := resource.Value, resource.Error
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	allocated := MoneroWallet_CreateAddress(ctx, cfg, "daochi-"+id, errPaymentUnavailable)
	address, index, err := allocated.Address, allocated.Index, allocated.Error
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	expiresAt := time.Now().UTC().Add(45 * time.Minute).Format(CanonicalTimestampLayout)
	_, err = s.Database.ExecContext(ctx, `
INSERT INTO token_payment_intents(id,provider,account_id,app_id,product_id,asset_id,token_units,
	provider_amount,provider_address,provider_ref,status,expires_at)
VALUES(?1,'monero',?2,?3,?4,?5,?6,?7,?8,?9,'pending',?10)`,
		id, accountID, appID, product.ProductID, AssetID, product.TokenUnits,
		product.MoneroAtomicAmount, address, strconv.Itoa(index), expiresAt)
	if err != nil {
		return MoneroInvoiceResponse{}, err
	}
	return MoneroInvoiceResponse{
		ID:           id,
		AppID:        appID,
		Status:       "pending",
		ProductID:    product.ProductID,
		AssetID:      AssetID,
		TokenUnits:   product.TokenUnits,
		AtomicAmount: product.MoneroAtomicAmount,
		Address:      address,
		AddressIndex: index,
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Store) baselineInvoiceMoneroInvoice(ctx context.Context, accountID, id string) (MoneroInvoiceResponse, bool, error) {
	var out MoneroInvoiceResponse
	var receiptID string
	err := s.Database.QueryRowContext(ctx, `
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
		receiptResult := TokenLedger_ByID(s.Database, ctx, receiptID)
		receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
		if err != nil {
			return MoneroInvoiceResponse{}, false, err
		}
		if found {
			out.Receipt = &receipt
		}
	}
	return out, true, nil
}

func (s *Store) baselineInvoicePendingMoneroInvoices(ctx context.Context, limit int) ([]baselineInvoiceMoneroInvoiceRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.Database.QueryContext(ctx, `
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
	out := []baselineInvoiceMoneroInvoiceRecord{}
	for rows.Next() {
		var item baselineInvoiceMoneroInvoiceRecord
		var receiptID string
		if err := rows.Scan(&item.AccountID, &item.Invoice.ID, &item.Invoice.AppID,
			&item.Invoice.Status, &item.Invoice.ProductID, &item.Invoice.AssetID,
			&item.Invoice.TokenUnits, &item.Invoice.AtomicAmount, &item.Invoice.Address,
			&item.Invoice.AddressIndex, &item.Invoice.PaymentID, &item.Invoice.ExpiresAt,
			&receiptID); err != nil {
			return nil, err
		}
		if receiptID != "" {
			receiptResult := TokenLedger_ByID(s.Database, ctx, receiptID)
			receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
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

func (s *Store) baselineInvoiceMarkMoneroInvoicePaid(ctx context.Context, accountID, id, receiptID, paymentRef string) error {
	res, err := s.Database.ExecContext(ctx, `
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

func (s *Store) baselineInvoiceMarkMoneroInvoiceExpired(ctx context.Context, accountID, id string) error {
	_, err := s.Database.ExecContext(ctx, `
UPDATE token_payment_intents
SET status='expired', updated_at=CURRENT_TIMESTAMP
WHERE account_id=?1 AND id=?2 AND provider='monero' AND status='pending'`,
		accountID, id)
	return err
}

// baselineInvoiceExpiredMoneroInvoices lists expired unpaid invoices from the recent
// lookback window for the late-payment sweep.
func (s *Store) baselineInvoiceExpiredMoneroInvoices(ctx context.Context, limit int) ([]baselineInvoiceMoneroInvoiceRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(CanonicalTimestampLayout)
	rows, err := s.Database.QueryContext(ctx, `
SELECT account_id,id,app_id,status,product_id,asset_id,token_units,provider_amount,
	provider_address,provider_ref,provider_payment_id,expires_at,receipt_id
FROM token_payment_intents
WHERE provider='monero' AND status='expired' AND receipt_id='' AND expires_at>=?1
ORDER BY created_at
LIMIT ?2`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []baselineInvoiceMoneroInvoiceRecord{}
	for rows.Next() {
		var item baselineInvoiceMoneroInvoiceRecord
		var receiptID string
		if err := rows.Scan(&item.AccountID, &item.Invoice.ID, &item.Invoice.AppID,
			&item.Invoice.Status, &item.Invoice.ProductID, &item.Invoice.AssetID,
			&item.Invoice.TokenUnits, &item.Invoice.AtomicAmount, &item.Invoice.Address,
			&item.Invoice.AddressIndex, &item.Invoice.PaymentID, &item.Invoice.ExpiresAt,
			&receiptID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// baselineInvoiceSettleExpiredMoneroInvoice transitions an expired invoice to paid after
// a late payment was credited by the sweep.
func (s *Store) baselineInvoiceSettleExpiredMoneroInvoice(ctx context.Context, accountID, id, receiptID, paymentRef string) error {
	res, err := s.Database.ExecContext(ctx, `
UPDATE token_payment_intents
SET status='paid', receipt_id=?3, provider_payment_id=?4, updated_at=CURRENT_TIMESTAMP
WHERE account_id=?1 AND id=?2 AND provider='monero' AND status='expired' AND receipt_id=''`,
		accountID, id, receiptID, paymentRef)
	if err != nil {
		return err
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("expired invoice no longer unsettled")
	}
	return nil
}
