package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type unlockResponse struct {
	Product    string `json:"product"`
	Unlocked   bool   `json:"unlocked"`
	PriceUnits int64  `json:"price_units"`
	Balance    int64  `json:"balance"`
	ReceiptID  string `json:"receipt_id"`
}

func unlockFixture(t *testing.T) (*Server, *Store, http.Handler, ed25519.PrivateKey) {
	t.Helper()
	server, store, _ := testServer(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Cfg.WaoziIssuerPublicKey = public
	server.Cfg.WaoziIssuerPrivateKey = private
	return server, store, server.Routes(), private
}

func creditDew(t *testing.T, store *Store, private ed25519.PrivateKey, account, payment string, units int64) {
	t.Helper()
	credit := TokenLedger_CreditPayment(store.Database, context.Background(), private, "monero", payment, TokenEventInput{
		AccountID: account, EventType: "credit", AmountDelta: units, SourceType: "monero", SourceRef: payment,
	}, errTokenIssuerReadOnly)
	if credit.Error != nil {
		t.Fatal(credit.Error)
	}
}

func postUnlock(t *testing.T, handler http.Handler, token, body string, status int) unlockResponse {
	t.Helper()
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/unlocks", token, []byte(body))
	if res.Code != status {
		t.Fatalf("unlock %s: %d %s", body, res.Code, res.Body.String())
	}
	var value unlockResponse
	if status == 200 {
		if res.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("unlock response may be cached")
		}
		if err := json.Unmarshal(res.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
	}
	return value
}

func TestUnlockChargesTheServerPriceOnce(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	owner := newTestIdentity(t, handler, 0x81)
	creditDew(t, store, private, owner.UserID, "unlock-fixture", 30*UnitsPerDew)
	ctx := context.Background()
	first := postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 200)
	if !first.Unlocked || first.Product != TaiChi || first.PriceUnits != 10000000 ||
		first.Balance != 20000000 || first.ReceiptID == "" {
		t.Fatalf("first unlock: %+v", first)
	}
	again := postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 200)
	if again != first {
		t.Fatalf("repeat unlock: %+v, want %+v", again, first)
	}
	balance := TokenLedger_Balance(store.Database, ctx, owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 20*UnitsPerDew {
		t.Fatalf("balance after unlocks: %+v", balance)
	}
	var debits int
	if err := store.Database.QueryRow(`SELECT COUNT(*) FROM token_ledger WHERE account_id=? AND source_type='unlock'`,
		owner.UserID).Scan(&debits); err != nil || debits != 1 {
		t.Fatalf("unlock debits: %d, %v", debits, err)
	}
	receipt := TokenLedger_ByID(store.Database, ctx, first.ReceiptID)
	if receipt.Error != nil || !receipt.Found || receipt.Value.AmountDelta != -10000000 || receipt.Value.AppID != "inbe" ||
		!TokenReceipt_ValidSignature(private.Public().(ed25519.PublicKey), receipt.Value) {
		t.Fatalf("unlock receipt: %+v", receipt)
	}
	// A deleted and restored account keeps what it paid for, without a second charge.
	if _, err := store.Database.Exec(`DELETE FROM account_unlocks WHERE account_id=?`, owner.UserID); err != nil {
		t.Fatal(err)
	}
	restored := postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 200)
	if restored.ReceiptID != first.ReceiptID || restored.Balance != 20*UnitsPerDew {
		t.Fatalf("restored unlock: %+v", restored)
	}
}

func TestUnlockRejectsUnaffordableUnknownAndMalformedRequests(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	owner := newTestIdentity(t, handler, 0x82)
	creditDew(t, store, private, owner.UserID, "short-fixture", 9999999)
	postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 402)
	postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.unknown"}`, 404)
	postUnlock(t, handler, "", `{"product":"inbe.practice.taichi"}`, 401)
	postUnlock(t, handler, "not-a-token", `{"product":"inbe.practice.taichi"}`, 401)
	for _, body := range []string{
		``,
		`{}`,
		`{"product":""}`,
		`{"product":"tai chi"}`,
		`{"product":1}`,
		`{"product":"inbe.practice.taichi","price_units":1}`,
		`{"product":"inbe.practice.taichi","product":"other"}`,
		`{"product":"inbe.practice.taichi"} {}`,
	} {
		postUnlock(t, handler, owner.Token, body, 400)
	}
	balance := TokenLedger_Balance(store.Database, context.Background(), owner.UserID, AssetID)
	if balance.Error != nil || balance.Value != 9999999 {
		t.Fatalf("refused unlocks changed the balance: %+v", balance)
	}
	if owned := Unlock_Owned(store.Database, context.Background(), owner.UserID, TaiChi); owned.Error != nil || owned.Value {
		t.Fatalf("refused unlock was saved: %+v", owned)
	}
}

func TestUnlockTrialPrice(t *testing.T) {
	server, store, handler, private := unlockFixture(t)
	now := time.Now().Unix()
	read := func(token string) (unlocks []map[string]any, products []map[string]any) {
		t.Helper()
		res := tokenJSONRequest(t, handler, http.MethodGet, "/api/v1/unlocks", token, nil)
		if res.Code != 200 || res.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("list: %d %s", res.Code, res.Body.String())
		}
		var value struct {
			Unlocks  []map[string]any `json:"unlocks"`
			Products []map[string]any `json:"products"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if value.Unlocks == nil || len(value.Products) != 1 {
			t.Fatalf("list shape: %s", res.Body.String())
		}
		return value.Unlocks, value.Products
	}
	for index, tc := range []struct {
		trialUntil int64
		price      int64
		shown      int64
	}{
		{now + 3600, 6000000, now + 3600},
		{now - 1, 10000000, 0},
		{0, 10000000, 0},
	} {
		server.Cfg.UnlockTrialUntil = tc.trialUntil
		owner := newTestIdentity(t, handler, byte(0x90+index))
		unlocks, products := read(owner.Token)
		want := map[string]any{"product": TaiChi, "price_units": float64(tc.price),
			"regular_price_units": float64(10000000), "trial_until": float64(tc.shown)}
		if len(unlocks) != 0 || !equalJSONMaps(products[0], want) {
			t.Fatalf("trial until %d: %v %v", tc.trialUntil, unlocks, products)
		}
		// The same prices are public, for an app that has not signed in.
		public := httptest.NewRecorder()
		handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/api/v1/unlocks/products", nil))
		var prices struct {
			Products []map[string]any `json:"products"`
		}
		if public.Code != 200 || public.Header().Get("Cache-Control") != "no-store" ||
			json.Unmarshal(public.Body.Bytes(), &prices) != nil || len(prices.Products) != 1 ||
			!equalJSONMaps(prices.Products[0], want) || strings.Contains(public.Body.String(), "receipt") {
			t.Fatalf("public prices: %d %s", public.Code, public.Body.String())
		}
		creditDew(t, store, private, owner.UserID, "trial-fixture-"+owner.UserID[:8], 10*UnitsPerDew)
		unlocked := postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 200)
		if unlocked.PriceUnits != tc.price || unlocked.Balance != 10*UnitsPerDew-tc.price {
			t.Fatalf("trial until %d charged: %+v", tc.trialUntil, unlocked)
		}
		unlocks, _ = read(owner.Token)
		if len(unlocks) != 1 || unlocks[0]["product"] != TaiChi || unlocks[0]["receipt_id"] != unlocked.ReceiptID ||
			unlocks[0]["created_at"].(float64) < float64(now) {
			t.Fatalf("listed unlocks: %v", unlocks)
		}
	}
	if Unlock_Price(TaiChi, 99, 100) != 6000000 || Unlock_Price(TaiChi, 100, 100) != 10000000 {
		t.Fatal("trial ends at trial_until")
	}
}

func equalJSONMaps(actual, expected map[string]any) bool {
	left, _ := json.Marshal(actual)
	right, _ := json.Marshal(expected)
	return bytes.Equal(left, right)
}

func requestGrant(t *testing.T, handler http.Handler, token, product string, status int) PackGrant {
	t.Helper()
	res := tokenJSONRequest(t, handler, http.MethodPost, "/api/v1/unlocks/grant", token,
		[]byte(`{"product":"`+product+`"}`))
	if res.Code != status {
		t.Fatalf("grant %s: %d %s", product, res.Code, res.Body.String())
	}
	var value struct {
		Grant     string `json:"grant"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if status == 200 {
		if err := json.Unmarshal(res.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
	}
	return PackGrant{Grant: value.Grant, ExpiresAt: value.ExpiresAt}
}

func TestGatedPackNeedsAGrantForItsProduct(t *testing.T) {
	server, store, handler, private := unlockFixture(t)
	owner := newTestIdentity(t, handler, 0x83)
	other := newTestIdentity(t, handler, 0x84)
	releaseKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	manifest := AppManifest{ManifestVersion: 1, AppID: "inbe", DisplayName: "inbe",
		Status: "active", Keys: []AppKey{{KeyID: "release", Algorithm: "ed25519",
			PublicKey: hex.EncodeToString(releaseKey.Public().(ed25519.PublicKey)), Status: "active"}}}
	encoded, _ := json.Marshal(manifest)
	if err := AppStore_UpsertSignedManifest(store.Database, context.Background(),
		manifest, encoded, "inbe-fixture", "fixture", "fixture"); err != nil {
		t.Fatal(err)
	}
	pack := []byte("ZIB\x00tai chi pack")
	open := []byte("ZIB\x00open module")
	artifact := func(variant string, data []byte) Artifact {
		hash := sha256.Sum256(data)
		return Artifact{Variant: variant, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data))}
	}
	release := ReleaseV2{AppID: "inbe", Sequence: 1, Version: "1.0.0", Runtime: "kryon-app-v1",
		HostAPI: 1, ModuleAPI: 1, DataSchema: 1, KeyID: "release",
		Artifacts:    []Artifact{artifact("module", pack), artifact("standalone", open)},
		Dependencies: []Dependency{}}
	release.Signature = hex.EncodeToString(ed25519.Sign(releaseKey, []byte(PackageRelease_SigningMessage(release))))
	metadata, _ := json.Marshal(release)
	root := server.Cfg.DBPath + ".packages/inbe"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	gated := release.Artifacts[0].SHA256 + ".zib"
	plain := release.Artifacts[1].SHA256 + ".zib"
	for name, data := range map[string][]byte{
		"latest-v2.json":           metadata,
		gated:                      pack,
		plain:                      open,
		gated + ".release-v2.json": metadata,
		plain + ".release-v2.json": metadata,
		gated + ".product":         []byte("inbe.practice.taichi\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	get := func(path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v2/packages/inbe/"+path, nil))
		if res.Code != status {
			t.Fatalf("%s: %d %s", path, res.Code, res.Body.String())
		}
		return res
	}
	wire := httptest.NewServer(handler)
	t.Cleanup(wire.Close)
	head := func(path string, status int) *http.Response {
		t.Helper()
		request, err := http.NewRequest(http.MethodHead, wire.URL+"/api/v2/packages/inbe/"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := wire.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		if response.StatusCode != status {
			t.Fatalf("HEAD %s: %d", path, response.StatusCode)
		}
		if data, err := io.ReadAll(response.Body); err != nil || len(data) != 0 {
			t.Fatalf("HEAD returned bytes: %q, %v", data, err)
		}
		return response
	}

	requestGrant(t, handler, owner.Token, TaiChi, 403)
	requestGrant(t, handler, owner.Token, "inbe.practice.unknown", 403)
	requestGrant(t, handler, "", TaiChi, 401)
	requestGrant(t, handler, owner.Token, "tai chi", 400)
	creditDew(t, store, private, owner.UserID, "pack-fixture", 10*UnitsPerDew)
	postUnlock(t, handler, owner.Token, `{"product":"inbe.practice.taichi"}`, 200)
	issued := requestGrant(t, handler, owner.Token, TaiChi, 200)
	now := time.Now().Unix()
	if issued.ExpiresAt < now+3590 || issued.ExpiresAt > now+3610 || strings.ContainsAny(issued.Grant, "/+=?#%") {
		t.Fatalf("grant: %+v", issued)
	}
	requestGrant(t, handler, other.Token, TaiChi, 403)

	get(gated, 403)
	head(gated, 403)
	get(gated+"/", 404)
	get("latest/"+issued.Grant, 404)
	expired := PackGrant_Issue(private, TaiChi, now-1, errTokenIssuerReadOnly)
	_, stranger, _ := ed25519.GenerateKey(nil)
	forged := PackGrant_Issue(stranger, TaiChi, now+3600, errTokenIssuerReadOnly)
	otherProduct := PackGrant_Issue(private, "inbe.practice.yoga", now+3600, errTokenIssuerReadOnly)
	parts := strings.Split(issued.Grant, ".")
	tampered := base64.RawURLEncoding.EncodeToString([]byte(GrantPrefix+"\ninbe.practice.taichi\n9999999999")) + "." + parts[1]
	padded := parts[0] + "." + base64.URLEncoding.EncodeToString(mustDecodeGrantPart(t, parts[1]))
	for _, grant := range []string{expired.Grant, forged.Grant, otherProduct.Grant, tampered, padded,
		"garbage", parts[0], parts[0] + "." + parts[1] + "." + parts[1]} {
		get(gated+"/"+grant, 403)
		head(gated+"/"+grant, 403)
	}
	served := get(gated+"/"+issued.Grant, 200)
	if !bytes.Equal(served.Body.Bytes(), pack) || served.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("gated pack: %q %v", served.Body.String(), served.Header())
	}
	checked := head(gated+"/"+issued.Grant, 200)
	if checked.Header.Get("ETag") != `"`+release.Artifacts[0].SHA256+`"` ||
		checked.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("HEAD authorization lost the verified identity or privacy: %v", checked.Header)
	}

	for _, path := range []string{plain, plain + "/" + issued.Grant, plain + "/garbage"} {
		res := get(path, 200)
		if !bytes.Equal(res.Body.Bytes(), open) || res.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("plain artifact %s: %v", path, res.Header())
		}
	}

	// The v1 route has no grant form, so it never serves a gated pack.
	v1 := Release{AppID: "inbe", Sequence: 1, Version: "1.0.0", Runtime: "kryon-desktop-v1",
		SHA256: release.Artifacts[0].SHA256, Size: int64(len(pack)), KeyID: "release"}
	v1.Signature = hex.EncodeToString(ed25519.Sign(releaseKey, []byte(BundleHttp_SigningMessage(v1))))
	v1Metadata, _ := json.Marshal(v1)
	if err := os.WriteFile(filepath.Join(root, "latest.json"), v1Metadata, 0600); err != nil {
		t.Fatal(err)
	}
	legacy := httptest.NewRecorder()
	handler.ServeHTTP(legacy, httptest.NewRequest(http.MethodGet, "/api/v1/packages/inbe/"+gated, nil))
	if legacy.Code != 403 {
		t.Fatalf("v1 gated pack: %d %s", legacy.Code, legacy.Body.String())
	}

	// An unreadable product file keeps the artifact closed to every grant.
	if err := os.Remove(filepath.Join(root, gated+".product")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, gated+".product"), 0700); err != nil {
		t.Fatal(err)
	}
	get(gated+"/"+issued.Grant, 403)
	head(gated+"/"+issued.Grant, 403)
	if err := os.Remove(filepath.Join(root, gated+".product")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, gated+".product"), []byte("not a product name"), 0600); err != nil {
		t.Fatal(err)
	}
	get(gated+"/"+issued.Grant, 403)
}

func mustDecodeGrantPart(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestPackGrantFormat(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issued := PackGrant_Issue(private, TaiChi, 2000, errTokenIssuerReadOnly)
	if issued.Error != nil {
		t.Fatal(issued.Error)
	}
	parts := strings.Split(issued.Grant, ".")
	if len(parts) != 2 {
		t.Fatalf("grant: %s", issued.Grant)
	}
	payload := mustDecodeGrantPart(t, parts[0])
	if string(payload) != "daochi-pack-grant-v1\ninbe.practice.taichi\n2000" ||
		!ed25519.Verify(public, payload, mustDecodeGrantPart(t, parts[1])) {
		t.Fatalf("payload: %q", payload)
	}
	if !PackGrant_Valid(public, issued.Grant, TaiChi, 1999) || PackGrant_Valid(public, issued.Grant, TaiChi, 2000) {
		t.Fatal("grant expiry")
	}
	if PackGrant_Valid(nil, issued.Grant, TaiChi, 1) || PackGrant_Valid(public, issued.Grant, "", 1) {
		t.Fatal("grant accepted without a key or product")
	}
	if missing := PackGrant_Issue(nil, TaiChi, 2000, errTokenIssuerReadOnly); missing.Error != errTokenIssuerReadOnly {
		t.Fatalf("grant without issuer: %+v", missing)
	}
}

func TestRescaleDewIsIdempotent(t *testing.T) {
	_, store, handler, private := unlockFixture(t)
	ctx := context.Background()
	rich := newTestIdentity(t, handler, 0x85)
	spent := newTestIdentity(t, handler, 0x86)
	empty := newTestIdentity(t, handler, 0x87)
	creditDew(t, store, private, rich.UserID, "rescale-rich", 14*UnitsPerDew)
	creditDew(t, store, private, spent.UserID, "rescale-spent", 10*UnitsPerDew)
	postUnlock(t, handler, rich.Token, `{"product":"inbe.practice.taichi"}`, 200)
	postUnlock(t, handler, spent.Token, `{"product":"inbe.practice.taichi"}`, 200)
	for _, statement := range []string{
		`INSERT INTO token_payment_intents(id,provider,account_id,product_id,asset_id,token_units,status,receipt_id) VALUES
			('pending','monero',?1,'dew','waozi:token',5000000,'pending',''),
			('late','monero',?1,'dew','waozi:token',3000000,'expired',''),
			('paid','monero',?1,'dew','waozi:token',7000000,'paid','receipt-paid')`,
		`INSERT INTO monero_deposits(tx_id,account_index,address_index,account_id,amount_atomic,status,rate_atomic_amount,rate_token_units,token_units,receipt_id) VALUES
			('waiting',0,1,?1,10,'confirming',1000000000000,5000000,50,''),
			('settled',0,1,?1,10,'credited',1000000000000,5000000,50,'receipt-settled')`,
	} {
		if _, err := store.Database.Exec(statement, empty.UserID); err != nil {
			t.Fatal(err)
		}
	}
	first := TokenRescale_Apply(store.Database, ctx, private, 20)
	if first.Error != nil || !first.Applied || first.Accounts != 1 || first.UnitsBefore != 4*UnitsPerDew ||
		first.UnitsAfter != 80*UnitsPerDew || first.Intents != 2 || first.Deposits != 1 {
		t.Fatalf("rescale: %+v", first)
	}
	check := func() {
		t.Helper()
		for account, want := range map[string]int64{rich.UserID: 80 * UnitsPerDew, spent.UserID: 0, empty.UserID: 0} {
			if got := TokenLedger_Balance(store.Database, ctx, account, AssetID); got.Error != nil || got.Value != want {
				t.Fatalf("balance %s: %+v, want %d", account[:8], got, want)
			}
		}
		for id, want := range map[string]int64{"pending": 100000000, "late": 60000000, "paid": 7000000} {
			var units int64
			if err := store.Database.QueryRow(`SELECT token_units FROM token_payment_intents WHERE id=?`, id).Scan(&units); err != nil || units != want {
				t.Fatalf("intent %s: %d, %v", id, units, err)
			}
		}
		for id, want := range map[string][2]int64{"waiting": {1000, 100000000}, "settled": {50, 5000000}} {
			var units, rate int64
			if err := store.Database.QueryRow(`SELECT token_units,rate_token_units FROM monero_deposits WHERE tx_id=?`, id).Scan(&units, &rate); err != nil ||
				units != want[0] || rate != want[1] {
				t.Fatalf("deposit %s: %d/%d, %v", id, units, rate, err)
			}
		}
	}
	check()
	credits := TokenLedger_List(store.Database, ctx, rich.UserID, AssetID, 0)
	last := credits.Value[len(credits.Value)-1]
	if credits.Error != nil || last.SourceType != "rescale" || last.AmountDelta != 76*UnitsPerDew ||
		!TokenReceipt_ValidSignature(private.Public().(ed25519.PublicKey), last) {
		t.Fatalf("rescale credit: %+v", last)
	}
	again := TokenRescale_Apply(store.Database, ctx, private, 20)
	if again.Error != nil || again.Applied || again.Accounts != first.Accounts || again.UnitsAfter != first.UnitsAfter {
		t.Fatalf("second rescale: %+v", again)
	}
	check()
	if other := TokenRescale_Apply(store.Database, ctx, private, 30); other.Error == nil {
		t.Fatal("a second, different rescale was accepted")
	}
	if invalid := TokenRescale_Apply(store.Database, ctx, private, 1); invalid.Error == nil {
		t.Fatal("rescale factor 1 accepted")
	}
	checkpoint := TokenCheckpoint_Create(store.Database, ctx, private, errTokenIssuerReadOnly)
	if checkpoint.Error != nil || checkpoint.Value.LedgerSeq != last.LedgerSeq {
		t.Fatalf("checkpoint: %+v", checkpoint)
	}
}
