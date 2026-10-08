package main

import (
	"testing"
)

func TestBuiltinLumiCollectionIsExactPrivateAndDurable(t *testing.T) {
	_, store, _ := testServer(t)
	for round := 0; round < 2; round++ {
		if err := AppStore_SeedBuiltin(store.Database, t.Context()); err != nil {
			t.Fatal(err)
		}
		result := AppStore_ByID(store.Database, t.Context(), "inbe")
		if result.Error != nil || !result.Found {
			t.Fatal("built-in app registration unavailable")
		}
		found := false
		for _, collection := range result.Value.Collections {
			if collection.CollectionPrefix == "private.inbe.v2.lumi" {
				found = collection.Visibility == "private" && collection.SchemaVersion == 2
			}
		}
		if !found {
			t.Fatal("isolated Lumi collection is not registered with its private schema")
		}
		for _, collection := range []string{"private.inbe.v2.diary", "private.inbe.v2.feedback", "private.inbe.v2.unlisted"} {
			owned := AppStore_OwnsCollection(store.Database, t.Context(), "inbe", collection)
			if owned.Error != nil || owned.Value {
				t.Fatal("built-in isolated Lumi declaration widened another collection")
			}
		}
		required := false
		for _, feature := range result.Value.Features {
			if feature.ID != "sync.private_records" {
				continue
			}
			for _, collection := range feature.Collections {
				if collection == "private.inbe.v2.lumi" {
					required = feature.RequiresSignedTx
				}
			}
		}
		if !required {
			t.Fatal("isolated Lumi owner sync does not require signed transactions")
		}
	}
}
