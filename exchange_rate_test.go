package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const (
	rateCoinGeckoBody = `{"monero":{"usd":542.52,"last_updated_at":1792089873}}`
	rateKrakenBody    = `{"error":[],"result":{"XXMRZUSD":{"a":["542.91000000","1","1.000"],"b":["542.64000000","1","1.000"],"c":["542.60000000","0.82257620"]}}}`
	ratePaprikaBody   = `{"id":"xmr-monero","quotes":{"USD":{"price":542.2168378729268,"volume_24h":166391284.9}}}`
)

func rateQuotes(values ...int64) []RateQuote {
	names := []string{"a", "b", "c", "d"}
	quotes := make([]RateQuote, len(values))
	for index, value := range values {
		quotes[index] = RateQuote{Name: names[index], Cents: value}
	}
	return quotes
}

func TestExchangeRateCombineKeepsTheMedianOfAgreeingSources(t *testing.T) {
	cases := []struct {
		quotes  []RateQuote
		cents   int64
		sources []string
	}{
		{rateQuotes(54252, 54260), 54256, []string{"a", "b"}},
		{rateQuotes(54300, 54252, 54260), 54260, []string{"a", "b", "c"}},
		// An outlier more than 10% from the median is dropped.
		{rateQuotes(54252, 70000, 54260), 54256, []string{"a", "c"}},
		{rateQuotes(54252, 54260, 1), 54256, []string{"a", "b"}},
		// One source alone, or two that disagree, give no rate.
		{rateQuotes(54252), 0, []string{}},
		{rateQuotes(), 0, []string{}},
		{rateQuotes(40000, 60000), 0, []string{}},
		{rateQuotes(40000, 54260, 70000), 0, []string{}},
	}
	for _, test := range cases {
		rate := ExchangeRate_Combine(test.quotes)
		if rate.Cents != test.cents || !reflect.DeepEqual(rate.Sources, test.sources) {
			t.Fatalf("Combine(%v) = %d %v, want %d %v", test.quotes, rate.Cents, rate.Sources, test.cents, test.sources)
		}
	}
}

func TestExchangeRateParsersReadEachSource(t *testing.T) {
	cases := []struct {
		parse RateParser
		body  string
		value float64
	}{
		{ExchangeRate_ParseCoinGecko, rateCoinGeckoBody, 542.52},
		{ExchangeRate_ParseKraken, rateKrakenBody, 542.60},
		{ExchangeRate_ParsePaprika, ratePaprikaBody, 542.2168378729268},
	}
	for _, test := range cases {
		price := test.parse([]byte(test.body))
		if price.Error != nil || price.Value != test.value {
			t.Fatalf("parse %s = %v %v", test.body, price.Value, price.Error)
		}
	}
	if ExchangeRate_ParseKraken([]byte(`{"error":["EQuery:Unknown asset pair"],"result":{}}`)).Error == nil {
		t.Fatal("kraken error accepted")
	}
	if ExchangeRate_ParseKraken([]byte(`{"error":[],"result":{}}`)).Error == nil {
		t.Fatal("missing kraken ticker accepted")
	}
	if ExchangeRate_ParseCoinGecko([]byte(`not json`)).Error == nil {
		t.Fatal("malformed source accepted")
	}
}

func rateSource(t *testing.T, name string, parse RateParser, status int, body string) RateSource {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("User-Agent") == "" {
			t.Error("rate source request is not a plain GET")
		}
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return RateSource{Name: name, Url: server.URL, Parse: parse}
}

func rateReply(t *testing.T, handler http.Handler) (RateReply, string, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/rates", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("rates status %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("rates cache %q", recorder.Header().Get("Cache-Control"))
	}
	var reply RateReply
	if err := json.Unmarshal(recorder.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply, recorder.Body.String(), recorder
}

func TestExchangeRateRefreshPersistsServesAndExpires(t *testing.T) {
	server, store, _ := testServer(t)
	server.Cfg.MoneroRateAtomicAmount = 1000000000000
	server.Cfg.MoneroRateTokenUnits = 1000000000
	handler := server.Routes()
	ctx := context.Background()
	now := time.Now().Unix()
	sources := []RateSource{
		rateSource(t, "coingecko", ExchangeRate_ParseCoinGecko, 200, rateCoinGeckoBody),
		rateSource(t, "kraken", ExchangeRate_ParseKraken, 200, rateKrakenBody),
		rateSource(t, "coinpaprika", ExchangeRate_ParsePaprika, 200, ratePaprikaBody),
	}
	if err := ExchangeRate_Refresh(ctx, store.Database, sources, now); err != nil {
		t.Fatal(err)
	}
	reply, body, _ := rateReply(t, handler)
	want := RateReply{XmrUsdCents: 54252, UpdatedAt: now, Sources: []string{"coingecko", "kraken", "coinpaprika"},
		XmrAtomicUnits: 1000000000000, TokenUnits: 1000000000}
	if !reflect.DeepEqual(reply, want) {
		t.Fatalf("rates reply %s", body)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil || len(fields) != 5 {
		t.Fatalf("rates reply has other fields: %s", body)
	}

	// A restart loads the stored rate; an empty database holds none.
	other, err := OpenStore(filepath.Join(t.TempDir(), "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := ExchangeRate_Load(other.Database, ctx); err != nil {
		t.Fatal(err)
	}
	if rate := ExchangeRate_Current(now); rate.Cents != 0 || rate.Sources == nil || len(rate.Sources) != 0 {
		t.Fatalf("empty store kept a rate: %+v", rate)
	}
	if err := ExchangeRate_Load(store.Database, ctx); err != nil {
		t.Fatal(err)
	}
	if rate := ExchangeRate_Current(now); rate.Cents != 54252 || rate.UpdatedAt != now ||
		!reflect.DeepEqual(rate.Sources, []string{"coingecko", "kraken", "coinpaprika"}) {
		t.Fatalf("restart lost the rate: %+v", rate)
	}

	// Failed or out-of-range sources are skipped while two others agree.
	partial := []RateSource{
		rateSource(t, "coingecko", ExchangeRate_ParseCoinGecko, 200, `{"monero":{"usd":600.00}}`),
		rateSource(t, "kraken", ExchangeRate_ParseKraken, 503, `{}`),
		rateSource(t, "coinpaprika", ExchangeRate_ParsePaprika, 200, `{"quotes":{"USD":{"price":601.00}}}`),
		rateSource(t, "broken", ExchangeRate_ParseCoinGecko, 200, `{"monero":{"usd":0.5}}`),
	}
	if err := ExchangeRate_Refresh(ctx, store.Database, partial, now+600); err != nil {
		t.Fatal(err)
	}
	if rate := ExchangeRate_Current(now + 600); rate.Cents != 60050 || !reflect.DeepEqual(rate.Sources, []string{"coingecko", "coinpaprika"}) {
		t.Fatalf("partial refresh: %+v", rate)
	}

	// One source alone never replaces the kept rate.
	lonely := []RateSource{
		rateSource(t, "coingecko", ExchangeRate_ParseCoinGecko, 200, `{"monero":{"usd":900.00}}`),
		rateSource(t, "kraken", ExchangeRate_ParseKraken, 500, `{}`),
	}
	if err := ExchangeRate_Refresh(ctx, store.Database, lonely, now+1200); err == nil {
		t.Fatal("one source was accepted alone")
	}
	if rate := ExchangeRate_Current(now + 1200); rate.Cents != 60050 || rate.UpdatedAt != now+600 {
		t.Fatalf("lonely refresh changed the rate: %+v", rate)
	}

	// Older than two hours, the node shows no rate at all.
	if err := ExchangeRate_Refresh(ctx, store.Database, sources, now-7201); err != nil {
		t.Fatal(err)
	}
	stale, staleBody, _ := rateReply(t, handler)
	if stale.XmrUsdCents != 0 || stale.UpdatedAt != 0 || stale.Sources == nil || len(stale.Sources) != 0 ||
		stale.XmrAtomicUnits != 1000000000000 || stale.TokenUnits != 1000000000 {
		t.Fatalf("stale rate shown: %s", staleBody)
	}
	if want := `"sources":[]`; !json.Valid([]byte(staleBody)) || !containsText(staleBody, want) {
		t.Fatalf("stale sources not an empty list: %s", staleBody)
	}

	// Without a configured Dew ratio the ratio fields are zero.
	server.Cfg.MoneroRateAtomicAmount = 0
	if unset, unsetBody, _ := rateReply(t, handler); unset.XmrAtomicUnits != 0 || unset.TokenUnits != 0 {
		t.Fatalf("unset ratio shown: %s", unsetBody)
	}
}

func containsText(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}

func TestExchangeRateRunLoadsThenRefreshesUntilCanceled(t *testing.T) {
	_, store, _ := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	sources := []RateSource{
		rateSource(t, "coingecko", ExchangeRate_ParseCoinGecko, 200, rateCoinGeckoBody),
		rateSource(t, "kraken", ExchangeRate_ParseKraken, 200, rateKrakenBody),
	}
	done := make(chan struct{})
	go func() {
		ExchangeRate_Run(store.Database, ctx, sources, time.Hour)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for ExchangeRate_Current(time.Now().Unix()).Cents != 54256 {
		if time.Now().After(deadline) {
			t.Fatal("first refresh did not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rate worker ignored cancellation")
	}
}
