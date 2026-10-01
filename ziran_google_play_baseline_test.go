// Google Play implementation before its Ziran port, retained as an independent oracle.
package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Server) baselineGoogleHandlePurchaseVerify(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.bearerUser(w, r)
	if !ok {
		return
	}
	decoded := PaymentRequest_ReadGoogle(w, r, s.cfg.MaxBodyBytes)
	req, body, err := decoded.Value, decoded.Body, decoded.Error
	if err != nil {
		Response_Error(w, http.StatusBadRequest, err.Error())
		return
	}
	issuer := TokenPolicy_Issuer(s.cfg, errTokenIssuerReadOnly)
	signer, err := issuer.Value, issuer.Error
	if err != nil {
		Response_Error(w, http.StatusServiceUnavailable, "token issuer unavailable")
		return
	}
	product, ok := s.cfg.TokenProducts[req.ProductID]
	if !ok {
		Response_Error(w, http.StatusBadRequest, "unknown product_id")
		return
	}
	existence := AppStore_Exists(s.store.Database, r.Context(), req.AppID)
	if exists, err := existence.Value, existence.Error; err != nil {
		slog.Error("google token purchase app lookup", "app", LogSafety_LogText(req.AppID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token purchase failed")
		return
	} else if !exists {
		Response_Error(w, http.StatusBadRequest, "unknown app_id")
		return
	}
	authorization := TokenPolicy_Authorize(s.store.Database, r.Context(), r, body, userID, req.AppID, AssetID, "purchase", s.verifier.Verify, errSignedTxReplay)
	signedTx, hasSignedTx, err := authorization.Value, authorization.Signed, authenticationError(authorization.Authentication)
	if err != nil {
		if hasSignedTx {
			SignedTx_Forget(s.store.Database, r.Context(), signedTx)
		}
		s.writeAuthError(w, err)
		return
	}
	completed := false
	defer func() {
		if hasSignedTx && !completed {
			SignedTx_Forget(s.store.Database, r.Context(), signedTx)
		}
	}()
	if len(s.cfg.GooglePackageNames) > 0 && !s.cfg.GooglePackageNames[req.PackageName] {
		Response_Error(w, http.StatusBadRequest, "package not allowed")
		return
	}
	paymentID, err := baselineGoogleVerifyPurchase(r.Context(), s.cfg, req)
	if err != nil {
		baselineGoogleWritePaymentError(w, err)
		return
	}
	paymentResult := TokenLedger_CreditPayment(s.store.Database, r.Context(), signer, "google_play", paymentID, TokenEventInput{
		AccountID:   userID,
		AppID:       req.AppID,
		EventType:   "credit",
		AmountDelta: product.TokenUnits,
		SourceType:  "google_play",
		SourceRef:   paymentID,
	}, errTokenIssuerReadOnly)
	receipt, _, err := paymentResult.Value, paymentResult.Created, paymentResult.Error
	if err != nil {
		slog.Error("google token credit", "user", LogSafety_LogText(userID), "payment", LogSafety_LogText(paymentID), "error", err)
		Response_Error(w, http.StatusInternalServerError, "token credit failed")
		return
	}
	if err := baselineGoogleConsumePurchase(r.Context(), s.cfg, req); err != nil {
		slog.Warn("google purchase consume failed after token credit", "user", LogSafety_LogText(userID), "payment", LogSafety_LogText(paymentID), "error", err)
	}
	balanceResult := TokenLedger_Balance(s.store.Database, r.Context(), userID, AssetID)
	balance, err := balanceResult.Value, balanceResult.Error
	if err != nil {
		Response_Error(w, http.StatusInternalServerError, "token balance failed")
		return
	}
	completed = true
	Response_JSON(w, http.StatusOK, TokenPurchaseResponse{Status: "ok", Balance: balance, Receipt: receipt})
}

func baselineGoogleWritePaymentError(w http.ResponseWriter, err error) {
	if errors.Is(err, errPaymentUnavailable) {
		Response_Error(w, http.StatusServiceUnavailable, "payment verifier unavailable")
		return
	}
	Response_Error(w, http.StatusBadRequest, err.Error())
}

func baselineGoogleVerifyPurchase(ctx context.Context, cfg Config, req GooglePurchaseVerifyRequest) (string, error) {
	if !cfg.baselineGoogleHasVerifier() {
		return "", errPaymentUnavailable
	}
	accessToken, err := baselineGoogleAccessToken(ctx, cfg)
	if err != nil {
		return "", errPaymentUnavailable
	}
	endpoint := GoogleAPIBaseURL + "/applications/" +
		url.PathEscape(req.PackageName) + "/purchases/products/" +
		url.PathEscape(req.ProductID) + "/tokens/" + url.PathEscape(req.PurchaseToken)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := GoogleHTTPClient.Do(httpReq)
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
		ref = TokenPolicy_ShortHash(req.PurchaseToken)
	}
	return req.PackageName + ":" + req.ProductID + ":" + ref, nil
}

func baselineGoogleConsumePurchase(ctx context.Context, cfg Config, req GooglePurchaseVerifyRequest) error {
	if !cfg.baselineGoogleHasVerifier() {
		return errPaymentUnavailable
	}
	accessToken, err := baselineGoogleAccessToken(ctx, cfg)
	if err != nil {
		return err
	}
	endpoint := GoogleAPIBaseURL + "/applications/" +
		url.PathEscape(req.PackageName) + "/purchases/products/" +
		url.PathEscape(req.ProductID) + "/tokens/" + url.PathEscape(req.PurchaseToken) + ":consume"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := GoogleHTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("google consume status %d", res.StatusCode)
	}
	return nil
}

type baselineGoogleServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

type baselineGoogleOAuthClientFile struct {
	Web       baselineGoogleOAuthClient `json:"web"`
	Installed baselineGoogleOAuthClient `json:"installed"`
}

type baselineGoogleOAuthClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURI     string   `json:"token_uri"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (cfg Config) baselineGoogleHasVerifier() bool {
	return cfg.GoogleServiceAccountJSON != "" ||
		(cfg.GoogleOAuthClientJSON != "" && cfg.GoogleOAuthRefreshToken != "")
}

func baselineGoogleAccessToken(ctx context.Context, cfg Config) (string, error) {
	if cfg.GoogleServiceAccountJSON != "" {
		return baselineGoogleServiceAccountAccessToken(ctx, cfg.GoogleServiceAccountJSON)
	}
	return baselineGoogleRefreshAccessToken(ctx, cfg.GoogleOAuthClientJSON, cfg.GoogleOAuthRefreshToken)
}

func baselineGoogleServiceAccountAccessToken(ctx context.Context, raw string) (string, error) {
	var account baselineGoogleServiceAccount
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
	segments := []string{baselineGoogleBase64JSON(header), baselineGoogleBase64JSON(claims)}
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
	res, err := GoogleHTTPClient.Do(req)
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

func baselineGoogleRefreshAccessToken(ctx context.Context, rawClient, refreshToken string) (string, error) {
	var file baselineGoogleOAuthClientFile
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
	res, err := GoogleHTTPClient.Do(req)
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

func baselineGoogleBase64JSON(value any) string {
	data, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(data)
}
