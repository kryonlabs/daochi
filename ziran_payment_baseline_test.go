// Payment boundary from f851e0f, retained as an independent regression oracle.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (s *Server) baselinePaymentTokenIssuerStatus() string {
	if len(s.cfg.WaoziIssuerPrivateKey) == ed25519.PrivateKeySize {
		return "ok"
	}
	if len(s.cfg.WaoziIssuerPublicKey) == ed25519.PublicKeySize {
		return "read_only"
	}
	return "disabled"
}

func (s *Server) baselinePaymentRequireTokenIssuer() (ed25519.PrivateKey, error) {
	if len(s.cfg.WaoziIssuerPrivateKey) != ed25519.PrivateKeySize {
		return nil, errTokenIssuerReadOnly
	}
	return s.cfg.WaoziIssuerPrivateKey, nil
}

func (s *Server) baselinePaymentHandleTokenAssets(w http.ResponseWriter, r *http.Request) {
	assetsResult := TokenAssets_List(s.store.db, r.Context())
	assets, err := assetsResult.Value, assetsResult.Error
	if err != nil {
		slog.Error("list token assets", "error", err)
		Response_Error(w, http.StatusInternalServerError, "token assets failed")
		return
	}
	Response_JSON(w, http.StatusOK, TokenAssetsResponse{Assets: assets})
}

func (s *Server) baselinePaymentHandleTokenProducts(w http.ResponseWriter, r *http.Request) {
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
	Response_JSON(w, http.StatusOK, TokenProductsResponse{Products: products})
}

func (s *Server) baselinePaymentHandleTokenIssuer(w http.ResponseWriter, r *http.Request) {
	Response_JSON(w, http.StatusOK, TokenIssuerResponse{
		IssuerID:  IssuerID,
		PublicKey: hex.EncodeToString(s.cfg.WaoziIssuerPublicKey),
		Algorithm: "Ed25519",
		Status:    s.baselinePaymentTokenIssuerStatus(),
	})
}

func (s *Server) baselinePaymentHandleTokenBalance(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	appID, appScoped, err := baselinePaymentTokenAppFilter(r)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var balance int64
	if appScoped {
		appBalanceResult := TokenLedger_AppBalance(s.store.db, r.Context(), userID, AssetID, appID)
		balance, err = appBalanceResult.Value, appBalanceResult.Error
	} else {
		balanceResult := TokenLedger_Balance(s.store.db, r.Context(), userID, AssetID)
		balance, err = balanceResult.Value, balanceResult.Error
	}
	if err != nil {
		slog.Error("token balance", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	Response_JSON(w, http.StatusOK, TokenBalanceResponse{
		AccountID: userID,
		AssetID:   AssetID,
		AppID:     appID,
		Balance:   balance,
	})
}

func (s *Server) baselinePaymentHandleTokenLedger(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	since, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("since")), 10, 64)
	appID, appScoped, err := baselinePaymentTokenAppFilter(r)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	var events []TokenReceipt
	if appScoped {
		appLedgerResult := TokenLedger_AppList(s.store.db, r.Context(), userID, AssetID, appID, since)
		events, err = appLedgerResult.Value, appLedgerResult.Error
	} else {
		ledgerResult := TokenLedger_List(s.store.db, r.Context(), userID, AssetID, since)
		events, err = ledgerResult.Value, ledgerResult.Error
	}
	if err != nil {
		slog.Error("token ledger", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token ledger failed")
		return
	}
	Response_JSON(w, http.StatusOK, TokenLedgerResponse{Events: events})
}

func (s *Server) baselinePaymentHandleTokenReceipt(w http.ResponseWriter, r *http.Request) {
	receiptID := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/receipts/")
	if !Identity_ValidResourceID(receiptID) {
		Response_Error(w, http.StatusBadRequest, "invalid receipt_id")
		return
	}
	// Receipt IDs are 128-bit capabilities; rate-limit probing by IP.
	if !s.allowRequest(r, "token-receipt:"+ClientAddress_FromRequest(r), 60, time.Minute) {
		Response_Error(w, http.StatusTooManyRequests, "too many receipt requests")
		return
	}
	receiptResult := TokenLedger_ByID(s.store.db, r.Context(), receiptID)
	receipt, found, err := receiptResult.Value, receiptResult.Found, receiptResult.Error
	if err != nil {
		slog.Error("token receipt", "receipt", LogSafety_LogText(receiptID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token receipt failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "receipt not found")
		return
	}
	Response_JSON(w, http.StatusOK, receipt)
}

func (s *Server) baselinePaymentHandleTokenSpend(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	req, body, err := baselinePaymentReadTokenSpendRequest(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	signer, err := s.baselinePaymentRequireTokenIssuer()
	if err != nil {
		Response_Error(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	if req.AssetID != AssetID {
		Response_Error(w, http.StatusBadRequest, "unsupported asset_id")
		return
	}
	existence := AppStore_Exists(s.store.db, r.Context(), req.AppID)
	if exists, err := existence.Value, existence.Error; err != nil {
		slog.Error("token spend app lookup", "app", LogSafety_LogText(req.AppID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token spend failed")
		return
	} else if !exists {
		Response_Error(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	signedTx, hasSignedTx, err := s.baselinePaymentAuthorizeTokenApp(r.Context(), r, body, userID, req.AppID, req.AssetID, "spend")
	if err != nil {
		if hasSignedTx {
			SignedTx_Forget(s.store.db, r.Context(), signedTx)
		}
		s.writeAuthError(w, err)
		return
	}
	completed := false
	defer func() {
		if hasSignedTx && !completed {
			SignedTx_Forget(s.store.db, r.Context(), signedTx)
		}
	}()
	sourceRef := req.Action + ":" + req.IdempotencyKey
	if req.Metadata != "" {
		sourceRef += ":" + baselinePaymentShortHash(req.Metadata)
	}
	spendResult := TokenLedger_Spend(s.store.db, r.Context(), signer, TokenEventInput{
		AccountID:   userID,
		AppID:       req.AppID,
		EventType:   "debit",
		AmountDelta: -req.Amount,
		SourceType:  "spend",
		SourceRef:   sourceRef,
	}, req.IdempotencyKey, errTokenIssuerReadOnly)
	receipt, balance, _, err := spendResult.Value, spendResult.Balance, spendResult.Created, spendResult.Error
	if err != nil {
		if strings.Contains(err.Error(), "insufficient balance") {
			Response_Error(w, http.StatusConflict, "insufficient balance")
			return
		}
		if strings.Contains(err.Error(), "idempotency key reused") {
			Response_Error(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("token spend", "user", LogSafety_LogText(userID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token spend failed")
		return
	}
	completed = true
	Response_JSON(w, http.StatusOK, TokenSpendResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func (s *Server) baselinePaymentHandleTokenCheckpointLatest(w http.ResponseWriter, r *http.Request) {
	checkpointResult := TokenCheckpoint_Latest(s.store.db, r.Context())
	checkpoint, found, err := checkpointResult.Value, checkpointResult.Found, checkpointResult.Error
	if err != nil {
		slog.Error("token checkpoint", "error", err)
		Response_Error(w, http.StatusInternalServerError, "token checkpoint failed")
		return
	}
	if !found {
		Response_Error(w, http.StatusNotFound, "checkpoint not found")
		return
	}
	Response_JSON(w, http.StatusOK, checkpoint)
}

func (s *Server) baselinePaymentHandleAdminManualCredit(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireAdmin(w, r, s.cfg.AdminToken) {
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		AppID     string `json:"app_id"`
		Amount    int64  `json:"amount"`
		SourceRef string `json:"source_ref"`
	}
	bodyResult := HttpBody_ReadJSON(w, r, s.cfg.MaxBodyBytes)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		Response_Error(w, http.StatusBadRequest, "invalid json")
		return
	}
	req.AccountID = strings.ToLower(strings.TrimSpace(req.AccountID))
	req.AppID = strings.TrimSpace(req.AppID)
	req.SourceRef = strings.TrimSpace(req.SourceRef)
	signer, err := s.baselinePaymentRequireTokenIssuer()
	if err != nil {
		Response_Error(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	if req.SourceRef == "" {
		req.SourceRef = "manual:" + time.Now().UTC().Format(time.RFC3339Nano)
	}
	paymentResult := TokenLedger_CreditPayment(s.store.db, r.Context(), signer, "admin", req.SourceRef, TokenEventInput{
		AccountID:   req.AccountID,
		AppID:       req.AppID,
		EventType:   "credit",
		AmountDelta: req.Amount,
		SourceType:  "admin",
		SourceRef:   req.SourceRef,
	}, errTokenIssuerReadOnly)
	receipt, _, err := paymentResult.Value, paymentResult.Created, paymentResult.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	balanceResult := TokenLedger_Balance(s.store.db, r.Context(), req.AccountID, AssetID)
	balance, err := balanceResult.Value, balanceResult.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	Response_JSON(w, http.StatusOK, TokenPurchaseResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func (s *Server) baselinePaymentHandleAdminTokenCheckpoint(w http.ResponseWriter, r *http.Request) {
	if !HttpAuth_RequireAdmin(w, r, s.cfg.AdminToken) {
		return
	}
	signer, err := s.baselinePaymentRequireTokenIssuer()
	if err != nil {
		Response_Error(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	checkpointResult := TokenCheckpoint_Create(s.store.db, r.Context(), signer, errTokenIssuerReadOnly)
	checkpoint, err := checkpointResult.Value, checkpointResult.Error
	if err != nil {
		slog.Error("create token checkpoint", "error", err)
		Response_Error(w, http.StatusInternalServerError, "token checkpoint failed")
		return
	}
	Response_JSON(w, http.StatusOK, checkpoint)
}

func baselinePaymentReadTokenSpendRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (TokenSpendRequest, []byte, error) {
	var req TokenSpendRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
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
	if !Identity_ValidNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.AssetID == "" {
		req.AssetID = AssetID
	}
	if req.Amount <= 0 {
		return req, nil, errors.New("amount required")
	}
	if !Identity_ValidNamespace(req.Action) {
		return req, nil, errors.New("invalid action")
	}
	if !Identity_ValidClientID(req.IdempotencyKey) {
		return req, nil, errors.New("invalid idempotency_key")
	}
	return req, body, nil
}

func baselinePaymentReadGooglePurchaseVerifyRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (GooglePurchaseVerifyRequest, []byte, error) {
	var req GooglePurchaseVerifyRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
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
	if !Identity_ValidNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.PackageName == "" || req.ProductID == "" || req.PurchaseToken == "" {
		return req, nil, errors.New("purchase fields required")
	}
	return req, body, nil
}

func baselinePaymentReadMoneroInvoiceRequest(w http.ResponseWriter, r *http.Request, maxBody int64) (MoneroInvoiceRequest, []byte, error) {
	var req MoneroInvoiceRequest
	bodyResult := HttpBody_ReadJSON(w, r, maxBody)
	body, err := bodyResult.Value, bodyResult.Error
	if err != nil {
		return req, nil, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, nil, errors.New("invalid json")
	}
	req.AppID = strings.TrimSpace(req.AppID)
	req.ProductID = strings.TrimSpace(req.ProductID)
	if !Identity_ValidNamespace(req.AppID) {
		return req, nil, errors.New("invalid app_id")
	}
	if req.ProductID == "" {
		return req, nil, errors.New("product_id required")
	}
	return req, body, nil
}

func baselinePaymentTokenAppFilter(r *http.Request) (string, bool, error) {
	appID := strings.TrimSpace(r.URL.Query().Get("app_id"))
	if appID == "" {
		return "", false, nil
	}
	if !Identity_ValidNamespace(appID) {
		return "", false, errors.New("invalid app_id")
	}
	return appID, true, nil
}

func (s *Server) baselinePaymentAuthorizeTokenApp(ctx context.Context, r *http.Request, body []byte, accountID, appID, assetID, permission string) (SignedTxEnvelope, bool, error) {
	hasSignedTx := strings.TrimSpace(r.Header.Get("X-Daochi-Tx")) != ""
	var signedTx SignedTxEnvelope
	if hasSignedTx {
		header := SignedTx_ReadHeader(r)
		tx, err := header.Value, authenticationError(header.Authentication)
		if err != nil {
			return signedTx, false, err
		}
		if err := authenticationError(SignedTx_Verify(s.store.db, ctx, r, body, tx, accountID, appID, s.verifier.Verify, errSignedTxReplay)); err != nil {
			return signedTx, false, err
		}
		signedTx = tx
	}
	if !Scope_ValidTokenPolicyPermission(permission) {
		return signedTx, hasSignedTx, authError{status: http.StatusBadRequest, message: "invalid token permission"}
	}
	policyExists := AppStore_HasPolicy(s.store.db, ctx, appID)
	hasPolicy, err := policyExists.Value, policyExists.Error
	if err != nil {
		return signedTx, hasSignedTx, err
	}
	if !hasPolicy {
		return signedTx, hasSignedTx, nil
	}
	policyResult := AppStore_Permission(s.store.db, ctx, appID, assetID, permission)
	policy, ok, err := policyResult.Value, policyResult.Found, policyResult.Error
	if err != nil {
		return signedTx, hasSignedTx, err
	}
	if !ok {
		return signedTx, hasSignedTx, authError{status: http.StatusForbidden, message: "app token permission denied"}
	}
	if !hasSignedTx && (policy.LegacyUnsignedUntil == 0 || time.Now().Unix() > policy.LegacyUnsignedUntil) {
		return signedTx, false, authError{status: http.StatusUnauthorized, message: "signed transaction required"}
	}
	return signedTx, hasSignedTx, nil
}

func baselinePaymentShortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
