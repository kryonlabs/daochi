package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

type recordProvenanceFixture struct {
	key           MLDSA44KeyPairResult
	accountID     string
	publicKey     string
	authorization RecordProvenanceAuthorization
}

func newRecordProvenanceFixture(t *testing.T) recordProvenanceFixture {
	t.Helper()
	key := MlDsa44_KeyPair()
	if key.Error != nil {
		t.Fatal(key.Error)
	}
	accountID := Signing_SHA256Hex(key.PublicKey)
	return recordProvenanceFixture{
		key:       key,
		accountID: accountID,
		publicKey: hex.EncodeToString(key.PublicKey),
		authorization: RecordProvenanceAuthorization{
			Role:       RecordWriterRole(1),
			AccountID:  accountID,
			AppID:      "inbe",
			Collection: "private.inbe.v1.habits",
			Now:        2_000_000_000,
		},
	}
}

func provenanceMutation(fixture recordProvenanceFixture) RecordProvenanceMutation {
	return RecordProvenanceMutation{
		AccountID:   fixture.accountID,
		AppID:       "inbe",
		Collection:  "private.inbe.v1.habits",
		ID:          "record-1",
		Version:     7,
		ContentHash: strings.Repeat("a", 64),
		Timestamp:   1_800_000_000,
	}
}

func signProvenance(t *testing.T, fixture recordProvenanceFixture, mutation RecordProvenanceMutation) RecordProvenanceMutation {
	t.Helper()
	signed := MlDsa44_Sign([]byte(RecordProvenance_CanonicalRecordProvenanceMessage(mutation)), fixture.key.PrivateKey)
	if signed.Error != nil {
		t.Fatal(signed.Error)
	}
	mutation.Signature = hex.EncodeToString(signed.Value)
	return mutation
}

func verifyProvenance(fixture recordProvenanceFixture, mutation RecordProvenanceMutation, previous *RecordProvenanceState) RecordProvenanceResult {
	return RecordProvenance_VerifyRecordProvenance(mutation, fixture.publicKey, fixture.authorization, previous)
}

func TestTransportPeerRejectsForgedRecord(t *testing.T) {
	fixture := newRecordProvenanceFixture(t)
	mutation := signProvenance(t, fixture, provenanceMutation(fixture))
	original := verifyProvenance(fixture, mutation, nil)
	if !original.Verified || original.Error != nil {
		t.Fatalf("owner-signed record rejected: verified=%v error=%v", original.Verified, original.Error)
	}

	forged := mutation
	forged.ContentHash = strings.Repeat("b", 64)
	if result := verifyProvenance(fixture, forged, nil); result.Verified || result.Error == nil {
		t.Fatal("forged record content was accepted")
	}

	other := newRecordProvenanceFixture(t)
	substituted := mutation
	substituted.AccountID = other.accountID
	substitutedAuthorization := RecordProvenanceAuthorization{
		Role:       RecordWriterRole(1),
		AccountID:  other.accountID,
		AppID:      "inbe",
		Collection: "private.inbe.v1.habits",
		Now:        2_000_000_000,
	}
	if result := RecordProvenance_VerifyRecordProvenance(substituted, other.publicKey, substitutedAuthorization, nil); result.Verified || result.Error == nil {
		t.Fatal("owner substitution was accepted")
	}
}

func TestTransportPeerRejectsForgedTombstone(t *testing.T) {
	fixture := newRecordProvenanceFixture(t)
	record := signProvenance(t, fixture, provenanceMutation(fixture))
	tombstone := record
	tombstone.Tombstone = true
	if result := verifyProvenance(fixture, tombstone, nil); result.Verified || result.Error == nil {
		t.Fatal("record signature was accepted as a tombstone")
	}

	validTombstone := tombstone
	validTombstone.Version = record.Version + 1
	validTombstone = signProvenance(t, fixture, validTombstone)
	state := verifyProvenance(fixture, record, nil).State
	verified := verifyProvenance(fixture, validTombstone, &state)
	if !verified.Verified || verified.Error != nil {
		t.Fatalf("owner-signed tombstone rejected: verified=%v error=%v", verified.Verified, verified.Error)
	}
	if !verified.State.Signed {
		t.Fatal("signed tombstone state was not retained")
	}
}

func TestRecordSignatureBindsAccountAppCollectionIDVersionContent(t *testing.T) {
	fixture := newRecordProvenanceFixture(t)
	base := signProvenance(t, fixture, provenanceMutation(fixture))
	changes := []RecordProvenanceMutation{
		func() RecordProvenanceMutation {
			value := base
			value.AccountID = strings.Repeat("c", 64)
			return value
		}(),
		func() RecordProvenanceMutation { value := base; value.AppID = "other"; return value }(),
		func() RecordProvenanceMutation {
			value := base
			value.Collection = "private.other.v1.data"
			return value
		}(),
		func() RecordProvenanceMutation { value := base; value.ID = "record-2"; return value }(),
		func() RecordProvenanceMutation { value := base; value.Version = base.Version + 1; return value }(),
		func() RecordProvenanceMutation {
			value := base
			value.ContentHash = strings.Repeat("d", 64)
			return value
		}(),
		func() RecordProvenanceMutation { value := base; value.Timestamp = base.Timestamp + 1; return value }(),
		func() RecordProvenanceMutation { value := base; value.Tombstone = true; return value }(),
	}
	for index, changed := range changes {
		authorization := fixture.authorization
		authorization.AccountID = changed.AccountID
		authorization.AppID = changed.AppID
		authorization.Collection = changed.Collection
		result := RecordProvenance_VerifyRecordProvenance(changed, fixture.publicKey, authorization, nil)
		if result.Verified || result.Error == nil {
			t.Fatalf("mutation field %d was not covered by the signature", index)
		}
	}

	otherOwner := newRecordProvenanceFixture(t)
	accountSubstitution := base
	accountSubstitution.AccountID = otherOwner.accountID
	otherAuthorization := fixture.authorization
	otherAuthorization.AccountID = otherOwner.accountID
	if result := RecordProvenance_VerifyRecordProvenance(accountSubstitution, otherOwner.publicKey, otherAuthorization, nil); result.Verified || result.Error == nil {
		t.Fatal("signature context did not bind the account identity")
	}
}

func TestRecordProvenanceReplayRollback(t *testing.T) {
	fixture := newRecordProvenanceFixture(t)
	first := signProvenance(t, fixture, provenanceMutation(fixture))
	state := verifyProvenance(fixture, first, nil).State

	replay := verifyProvenance(fixture, first, &state)
	if replay.Verified || replay.Error == nil {
		t.Fatal("exact signed mutation replay was accepted")
	}

	rollback := first
	rollback.Version = first.Version - 1
	rollback = signProvenance(t, fixture, rollback)
	if result := verifyProvenance(fixture, rollback, &state); result.Verified || result.Error == nil {
		t.Fatal("older signed mutation was accepted")
	}

	timestampRollback := first
	timestampRollback.Version = first.Version + 1
	timestampRollback.Timestamp = first.Timestamp - 1
	timestampRollback = signProvenance(t, fixture, timestampRollback)
	if result := verifyProvenance(fixture, timestampRollback, &state); result.Verified || result.Error == nil {
		t.Fatal("newer version with an older timestamp was accepted")
	}

	foreignState := state
	foreignState.ID = "different-record"
	if result := verifyProvenance(fixture, first, &foreignState); result.Verified || result.Error == nil {
		t.Fatal("state for another record was accepted")
	}

	unknown := fixture.authorization
	unknown.Role = RecordWriterRole(0)
	if result := RecordProvenance_VerifyRecordProvenance(first, fixture.publicKey, unknown, nil); result.Verified || result.Error == nil {
		t.Fatal("unknown writer role was accepted")
	}

	outOfRange := fixture.authorization
	outOfRange.Role = RecordWriterRole(3)
	if result := RecordProvenance_VerifyRecordProvenance(first, fixture.publicKey, outOfRange, nil); result.Verified || result.Error == nil {
		t.Fatal("out-of-range writer role was accepted")
	}

	future := first
	future.Version = first.Version + 1
	future.Timestamp = fixture.authorization.Now + RecordProvenanceMaxFutureSeconds + 1
	future = signProvenance(t, fixture, future)
	if result := verifyProvenance(fixture, future, &state); result.Verified || result.Error == nil {
		t.Fatal("mutation beyond the future-time bound was accepted")
	}

	missingNow := fixture.authorization
	missingNow.Now = 0
	if result := RecordProvenance_VerifyRecordProvenance(first, fixture.publicKey, missingNow, nil); result.Verified || result.Error == nil {
		t.Fatal("mutation without a verification clock was accepted")
	}
}

func TestLegacyDelegatedWriterMigration(t *testing.T) {
	fixture := newRecordProvenanceFixture(t)
	legacyAuthorization := fixture.authorization
	legacyAuthorization.Role = RecordWriterRole(2)
	legacyAuthorization.DelegatedWriterID = "trusted-peer"
	legacyAuthorization.DelegatedWriterExpiresAt = legacyAuthorization.Now + 1

	legacy := provenanceMutation(fixture)
	legacyResult := RecordProvenance_VerifyRecordProvenance(legacy, fixture.publicKey, legacyAuthorization, nil)
	if !legacyResult.Verified || legacyResult.Error != nil || legacyResult.State.Signed {
		t.Fatalf("explicit legacy delegated writer rejected: verified=%v error=%v signed=%v", legacyResult.Verified, legacyResult.Error, legacyResult.State.Signed)
	}

	invalidOwnerKey := legacyAuthorization
	if result := RecordProvenance_VerifyRecordProvenance(legacy, "00", invalidOwnerKey, nil); result.Verified || result.Error == nil {
		t.Fatal("legacy delegated writer accepted an invalid owner key")
	}

	signed := legacy
	signed.Version = legacy.Version + 1
	signed.Timestamp = legacy.Timestamp + 1
	signed = signProvenance(t, fixture, signed)
	migrated := RecordProvenance_VerifyRecordProvenance(signed, fixture.publicKey, legacyAuthorization, &legacyResult.State)
	if !migrated.Verified || migrated.Error != nil || !migrated.State.Signed {
		t.Fatalf("delegated writer owner-signature migration rejected: verified=%v error=%v signed=%v", migrated.Verified, migrated.Error, migrated.State.Signed)
	}

	downgrade := signed
	downgrade.Version = signed.Version + 1
	downgrade.Timestamp = signed.Timestamp + 1
	downgrade.Signature = ""
	if result := RecordProvenance_VerifyRecordProvenance(downgrade, fixture.publicKey, legacyAuthorization, &migrated.State); result.Verified || result.Error == nil {
		t.Fatal("signed delegated-writer state downgraded to unsigned")
	}

	implicit := legacyAuthorization
	implicit.DelegatedWriterID = ""
	if result := RecordProvenance_VerifyRecordProvenance(legacy, fixture.publicKey, implicit, nil); result.Verified || result.Error == nil {
		t.Fatal("missing delegated-writer identity was accepted")
	}
	expired := legacyAuthorization
	expired.DelegatedWriterExpiresAt = expired.Now
	if result := RecordProvenance_VerifyRecordProvenance(legacy, fixture.publicKey, expired, nil); result.Verified || result.Error == nil {
		t.Fatal("expired delegated-writer trust was accepted")
	}
}
