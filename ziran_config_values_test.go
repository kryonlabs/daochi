package main

import (
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestZiranConfigSyncValues(t *testing.T) {
	values := []string{
		"", " \t\r\n", "\u00a0PULL\u2003", "receive", "from_peer", "FROM-PEER",
		"push", "send", "to_peer", "to-peer", "bidirectional", "both", "mirror",
		"readwrite", "read-write", "none", "off", "disabled", "FALSE", "0", "no",
		"1", "YES", "On", "unknown", "\xffPULL", "a|b a+b", "a\tb", "a++a| b",
	}
	for _, value := range values {
		if got, want := ConfigValues_SyncDirection(value), baselineSyncDirection(value); got != want {
			t.Errorf("direction(%q) = %q, want %q", value, got, want)
		}
		if got, want := ConfigValues_SyncList(value), baselineSyncList(value); !reflect.DeepEqual(got, want) {
			t.Errorf("list(%q) = %#v, want %#v", value, got, want)
		}
		for _, fallback := range []bool{false, true} {
			if got, want := ConfigValues_Bool(value, fallback), baselineBoolValue(value, fallback); got != want {
				t.Errorf("bool(%q, %v) = %v, want %v", value, fallback, got, want)
			}
		}
	}
}

func TestZiranConfigPeerPolicyOrderAndNil(t *testing.T) {
	inputs := [][]string{
		nil, {}, {"invalid", "sync=", "apps=+++"},
		{"enabled=false", "sync=pull"}, {"sync=pull", "enabled=false"},
		{"enabled=false", "enabled=true"}, {"apps=a+b", "apps="},
		{"\u00a0MODE\u2003= BOTH", "APP_IDS=a|b a", "collections=x+y", "space_ids=one", "types=records", "enabled="},
		{"unknown=ignored", "direction=custom", "data=a=b"},
	}
	for _, fields := range inputs {
		got, want := ConfigValues_SyncPolicy(fields), baselineNodeSyncPolicyValue(fields)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("policy(%q) = %#v, want %#v", fields, got, want)
		}
	}
	raw := " ,First=https://one.example///;apps=a+b,Duplicate=https://one.example;sync=none,Second|https://two.example;enabled=false,=///,no-policy;unknown=ignored"
	if got, want := ConfigValues_Peers(raw), baselineNodePeersValue(raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("peers = %#v, want %#v", got, want)
	}
	for _, raw := range []string{"", " \u00a0", ",,,", "///", "name=///"} {
		if got := ConfigValues_Peers(raw); got != nil {
			t.Errorf("empty peers(%q) = %#v, want nil", raw, got)
		}
	}
}

func TestZiranConfigProductsLimitsAndDuplicates(t *testing.T) {
	values := []string{
		"", "product:1", "product:9223372036854775807:9223372036854775807",
		"product:9223372036854775808", "product:-9223372036854775808", "product:0",
		"product:+001:001", "product: 1", "product:1:bad", "product:1:-1",
		"product:1:9223372036854775808", ":1", "missing", "too:1:2:3",
		" duplicate:1:7,duplicate:2,duplicate:0:10,other:3:99 ", "\xffname:1",
	}
	for _, raw := range values {
		got, want := ConfigValues_Products(raw), baselineTokenProductsValue(raw)
		if got == nil || !reflect.DeepEqual(got, want) {
			t.Errorf("products(%q) = %#v, want %#v", raw, got, want)
		}
	}
}

func TestZiranConfigValuesArbitraryBytes(t *testing.T) {
	random := rand.New(rand.NewSource(17))
	for i := 0; i < 1000; i++ {
		data := make([]byte, random.Intn(128))
		if _, err := random.Read(data); err != nil {
			t.Fatal(err)
		}
		raw := string(data)
		if i%2 == 0 {
			raw = "One=https://one.example;apps=inbe|uku;enabled=false," + raw + ";mode=both"
		}
		if got, want := ConfigValues_Peers(raw), baselineNodePeersValue(raw); !reflect.DeepEqual(got, want) {
			t.Fatalf("peers(%q) = %#v, want %#v", raw, got, want)
		}
		if got, want := ConfigValues_SyncList(raw), baselineSyncList(raw); !reflect.DeepEqual(got, want) {
			t.Fatalf("list(%q) = %#v, want %#v", raw, got, want)
		}
		if got, want := ConfigValues_Products(raw), baselineTokenProductsValue(raw); !reflect.DeepEqual(got, want) {
			t.Fatalf("products(%q) = %#v, want %#v", raw, got, want)
		}
	}
}

// These Go functions preserve the pre-port configuration parser contracts.
// Production parsing is canonical in config_values.zi.
func baselineNodePeersValue(raw string) []NodePeer {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var peers []NodePeer
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name := ""
		urlValue := item
		policyFields := []string{}
		if fields := strings.Split(item, ";"); len(fields) > 1 {
			urlValue = strings.TrimSpace(fields[0])
			policyFields = fields[1:]
		}
		if before, after, ok := strings.Cut(urlValue, "="); ok {
			name = strings.TrimSpace(before)
			urlValue = after
		} else if before, after, ok := strings.Cut(urlValue, "|"); ok {
			name = strings.TrimSpace(before)
			urlValue = after
		}
		urlValue = strings.TrimRight(strings.TrimSpace(urlValue), "/")
		if urlValue == "" || seen[urlValue] {
			continue
		}
		seen[urlValue] = true
		peers = append(peers, NodePeer{Name: name, URL: urlValue, Sync: baselineNodeSyncPolicyValue(policyFields)})
	}
	return peers
}

func baselineNodeSyncPolicyValue(fields []string) *NodeSyncPolicy {
	var policy NodeSyncPolicy
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "sync", "mode", "direction":
			policy.Direction = baselineSyncDirection(value)
		case "app", "apps", "app_id", "app_ids":
			policy.Apps = baselineSyncList(value)
		case "collection", "collections":
			policy.Collections = baselineSyncList(value)
		case "space", "spaces", "space_id", "space_ids":
			policy.Spaces = baselineSyncList(value)
		case "data", "type", "types":
			policy.Data = baselineSyncList(value)
		case "enabled":
			if !baselineBoolValue(value, true) {
				policy.Direction = "none"
			}
		}
	}
	if policy.Direction == "" && len(policy.Apps) == 0 && len(policy.Collections) == 0 &&
		len(policy.Spaces) == 0 && len(policy.Data) == 0 {
		return nil
	}
	if policy.Direction == "" {
		policy.Direction = "bidirectional"
	}
	return &policy
}

func baselineSyncDirection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "pull", "receive", "from_peer", "from-peer":
		return "pull"
	case "push", "send", "to_peer", "to-peer":
		return "push"
	case "bidirectional", "both", "mirror", "readwrite", "read-write":
		return "bidirectional"
	case "none", "off", "disabled", "false", "0", "no":
		return "none"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func baselineSyncList(value string) []string {
	value = strings.NewReplacer("|", "+", " ", "+").Replace(value)
	seen := map[string]bool{}
	var out []string
	for _, item := range strings.Split(value, "+") {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func baselineBoolValue(value string, fallback bool) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func baselineTokenProductsValue(raw string) map[string]TokenProduct {
	out := map[string]TokenProduct{}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" {
			continue
		}
		units, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || units <= 0 {
			continue
		}
		product := TokenProduct{ProductID: parts[0], TokenUnits: units}
		if len(parts) == 3 {
			atomic, err := strconv.ParseInt(parts[2], 10, 64)
			if err == nil && atomic > 0 {
				product.MoneroAtomicAmount = atomic
			}
		}
		out[product.ProductID] = product
	}
	return out
}
