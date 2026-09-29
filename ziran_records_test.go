package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// This fixture was extracted from the original Go declarations before their
// port. It protects exported field names, Go storage types, order and tags.
func TestZiranProtocolRecordsKeepReleasedLayout(t *testing.T) {
	data, err := os.ReadFile("testdata/protocol_records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records map[string][]struct {
			Name string
			Type string
			Tag  string
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	records := []any{
		AccountExportResponse{},
		SyncDiagnosticReport{},
		SyncRequest{},
		SyncChanges{},
		SyncResponse{},
		CleanData{},
		SyncLog{},
		SyncOp{},
		SocialSnapshot{},
		EncryptedPayload{},
		SignedAppGrantRequest{},
		AppRegistryResponse{},
		AppRegistration{},
		SignedAppRegistrationRequest{},
		AppManifest{},
		TokenPolicy{},
		AppKey{},
		AliasRequest{},
		AliasResponse{},
		AppCollection{},
		AppFeature{},
		AppGrant{},
		AppGrantRequest{},
		AppGrantsResponse{},
		AppRecordsResponse{},
		AppStorageUsage{},
		ChallengeResponse{},
		CleanHabitDay{},
		CollectionStorageUsage{},
		DeleteRequest{},
		DeleteWithKeyRequest{},
		EncryptedRecord{},
		Friend{},
		FriendRequest{},
		FriendRequestActionRequest{},
		FriendRequestCreateRequest{},
		FriendRequestResponse{},
		FriendRequestsResponse{},
		FriendStatRow{},
		FriendStatsResponse{},
		FriendsResponse{},
		GooglePurchaseVerifyRequest{},
		Habit{},
		HabitDay{},
		LegacyProtocol{},
		LoginRequest{},
		LoginResponse{},
		MeditationLog{},
		MoneroAccountAddress{},
		MoneroAddressResponse{},
		MoneroDeposit{},
		MoneroDepositsResponse{},
		MoneroInvoiceRequest{},
		MoneroInvoiceResponse{},
		MoneroRate{},
		NodePeer{},
		NodeStorageUsage{},
		NodeSyncPolicy{},
		NodeUsage{},
		ProfileIconRequest{},
		ProfileIconResponse{},
		ProfileMetric{},
		ProfileStatsRequest{},
		ProfileStatsResponse{},
		Session{},
		SessionRound{},
		StorageBucketUsage{},
		SyncAuditEntry{},
		SyncDiagnostics{},
		SyncResult{},
		TokenAsset{},
		TokenAssetsResponse{},
		TokenBalanceResponse{},
		TokenCheckpoint{},
		TokenIssuerResponse{},
		TokenLedgerResponse{},
		TokenProduct{},
		TokenProductsResponse{},
		TokenPurchaseResponse{},
		TokenReceipt{},
		TokenSpendRequest{},
		TokenSpendResponse{},
	}
	if len(records) != len(fixture.Records) {
		t.Fatal("record inventory differs from original layout fixture")
	}
	for _, record := range records {
		typ := reflect.TypeOf(record)
		t.Run(typ.Name(), func(t *testing.T) {
			fields, found := fixture.Records[typ.Name()]
			if !found || typ.NumField() != len(fields) {
				t.Fatal("record field inventory changed")
			}
			for index, expected := range fields {
				field := typ.Field(index)
				actualType := strings.ReplaceAll(field.Type.String(), "main.", "")
				if field.Name != expected.Name || actualType != expected.Type || string(field.Tag) != expected.Tag {
					t.Fatalf("field %d = %s %s %q; want %s %s %q", index,
						field.Name, actualType, field.Tag, expected.Name, expected.Type, expected.Tag)
				}
			}
		})
	}
}
