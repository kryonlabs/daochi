package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Captured before removal: the original wallet policy, transport, and payment
// inspector remain independent regression oracles, never production code.
type baselineMoneroTransferRPC struct {
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

func baselineValidMoneroRate(cfg Config) bool {
	return cfg.MoneroRateAtomicAmount > 0 && cfg.MoneroRateTokenUnits > 0
}

func baselineMoneroConfirmationsRequired(cfg Config) int64 {
	if cfg.MoneroConfirmationsRequired > 0 {
		return cfg.MoneroConfirmationsRequired
	}
	return 10
}

func baselineMoneroMinimumAtomicAmount(cfg Config) int64 {
	if cfg.MoneroMinimumAtomicAmount > 0 {
		return cfg.MoneroMinimumAtomicAmount
	}
	return 1
}

func baselineMoneroTokenUnits(amount, rateAtomic, rateTokens int64) (int64, error) {
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

func baselineCreateMoneroSubaddress(ctx context.Context, cfg Config, label string) (string, int, error) {
	if cfg.MoneroWalletRPCURL == "" {
		return "", 0, errPaymentUnavailable
	}
	var result struct {
		Address      string `json:"address"`
		AddressIndex int    `json:"address_index"`
	}
	if err := baselineMoneroRPC(ctx, cfg, "create_address", map[string]any{
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

// baselineMoneroInvoicePaymentState aggregates every transfer made to an invoice
// subaddress so partial payments can accumulate until they cover the
// price instead of only the first sufficiently-large transfer counting.
type baselineMoneroInvoicePaymentState struct {
	PaymentID       string // deterministic: sorted tx ids joined with "+"
	SeenAtomic      int64  // every transfer amount, confirmed or not
	ConfirmedAtomic int64  // transfers past the confirmation policy
}

func baselineInspectMoneroInvoicePayment(ctx context.Context, cfg Config, invoice MoneroInvoiceResponse) (baselineMoneroInvoicePaymentState, error) {
	state := baselineMoneroInvoicePaymentState{}
	if cfg.MoneroWalletRPCURL == "" {
		return state, errPaymentUnavailable
	}
	var result struct {
		In   []baselineMoneroTransferRPC `json:"in"`
		Pool []baselineMoneroTransferRPC `json:"pool"`
	}
	if err := baselineMoneroRPC(ctx, cfg, "get_transfers", map[string]any{
		"in":              true,
		"pending":         true,
		"pool":            true,
		"failed":          false,
		"account_index":   0,
		"subaddr_indices": []int{invoice.AddressIndex},
	}, &result); err != nil {
		return state, err
	}
	txids := []string{}
	seenTX := map[string]bool{}
	for _, tx := range append(result.Pool, result.In...) {
		if tx.TxID == "" || tx.Amount <= 0 ||
			tx.SubaddrIndex.Major != 0 || tx.SubaddrIndex.Minor != invoice.AddressIndex {
			continue
		}
		if seenTX[tx.TxID] {
			continue
		}
		seenTX[tx.TxID] = true
		state.SeenAtomic += tx.Amount
		txids = append(txids, tx.TxID)
		if tx.DoubleSpendSeen {
			continue
		}
		if tx.Confirmations >= baselineMoneroConfirmationsRequired(cfg) && !tx.Locked && tx.UnlockTime == 0 {
			state.ConfirmedAtomic += tx.Amount
		}
	}
	if len(txids) > 0 {
		sort.Strings(txids)
		state.PaymentID = strings.Join(txids, "+") + ":0:" + strconv.Itoa(invoice.AddressIndex)
	}
	return state, nil
}

func baselineMoneroRPC(ctx context.Context, cfg Config, method string, params map[string]any, out any) error {
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
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
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
