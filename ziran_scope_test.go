package main

import "testing"

func TestZiranCollectionScopeContracts(t *testing.T) {
	for _, test := range []struct {
		prefix string
		valid  bool
	}{
		{"inbe.habits", true},
		{"inbe.habit_days", true},
		{"inbe.sessions", true},
		{"account.v1.*", true},
		{"account.v1.profile", true},
		{"private.ukuvota.v1.records.*", true},
		{"friends.ukuvota.v9999.records", true},
		{"\u2003public.ukuvota.v1.records.*\u2003", true},
		{"", false},
		{"account.v0.*", false},
		{"account.v1.profile.*", false},
		{"private.ukuvota.v10000.*", false},
		{"private.ukuvota.v1..*", false},
		{"private.ukuvota.*", false},
		{"private.ukuvota.v1.records*", false},
	} {
		if got := Scope_ValidCollectionPrefix(test.prefix); got != test.valid {
			t.Errorf("prefix %q: got %v, want %v", test.prefix, got, test.valid)
		}
	}
	for _, test := range []struct {
		appID      string
		collection AppCollection
		owns       bool
	}{
		{"ukuvota", AppCollection{CollectionPrefix: "private.ukuvota.v1.records.*", Visibility: "private"}, true},
		{"ukuvota", AppCollection{CollectionPrefix: "private.other.v1.records.*", Visibility: "private"}, false},
		{"ukuvota", AppCollection{CollectionPrefix: "public.ukuvota.v1.records.*", Visibility: "private"}, false},
		{"inbe", AppCollection{CollectionPrefix: "inbe.habits", Visibility: "private"}, true},
		{"inbe", AppCollection{CollectionPrefix: "inbe.habits", Visibility: "public"}, false},
		{"ukuvota", AppCollection{CollectionPrefix: "inbe.habits", Visibility: "private"}, false},
	} {
		if got := Scope_AppOwnsDeclaredScope(test.appID, test.collection); got != test.owns {
			t.Errorf("app %q scope %#v: got %v, want %v", test.appID, test.collection, got, test.owns)
		}
	}
}

func TestZiranCollectionPrefixesKeepBoundariesAndSQLEscapes(t *testing.T) {
	for _, test := range []struct {
		collection string
		prefix     string
		matches    bool
	}{
		{"private.app.v1.records", "private.app.v1.records", true},
		{"private.app.v1.records.one", "private.app.v1.records.*", true},
		{"private.app.v1.records", "private.app.v1.records.*", false},
		{"private.app.v1.records_extra.one", "private.app.v1.records.*", false},
		{"private.other.v1.records.one", "private.app.v1.records.*", false},
	} {
		if got := Scope_CollectionMatchesPrefix(test.collection, test.prefix); got != test.matches {
			t.Errorf("collection %q prefix %q: got %v, want %v", test.collection, test.prefix, got, test.matches)
		}
	}
	if got := Scope_LikePatternForCollectionPrefix(`private.app_name.v1.rec%\ords.*`); got != `private.app\_name.v1.rec\%\\ords.%` {
		t.Fatalf("SQL wildcard escaping = %q", got)
	}
	collections := []AppCollection{{CollectionPrefix: "private.app.v1.records.*"}}
	if !Scope_DeclaresCollection(collections, collections[0].CollectionPrefix) ||
		Scope_DeclaresCollection(nil, collections[0].CollectionPrefix) ||
		Scope_DeclaresCollection(collections, "private.other.v1.records.*") {
		t.Fatal("declared collection matching changed")
	}
}
