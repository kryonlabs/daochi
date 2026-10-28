package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
)

func TestAliasDisplayCaseSavesWithoutPurchase(t *testing.T) {
	server, users, handler := premiumAliasFixture(t)
	user := users[0]
	if _, err := server.Store.Database.Exec("UPDATE server_users SET alias='moon' WHERE user_id_hash=?", user); err != nil {
		t.Fatal(err)
	}
	_, before := aliasState(t, server, user)
	for _, spelling := range []string{"Moon", "MOON", "mOoN"} {
		response := aliasRequest(server, handler, user, http.MethodPost, "/api/v1/account/alias", `{"alias":"`+spelling+`"}`)
		if response.Code != http.StatusOK {
			t.Fatalf("case edit: %d %s", response.Code, response.Body.String())
		}
		alias, balance := aliasState(t, server, user)
		if alias != spelling || balance != before {
			t.Fatalf("display %q, balance %d; wanted %q, %d", alias, balance, spelling, before)
		}
		quote := AliasPricing_Price(server.Store.Database, t.Context(), user, "moon", true)
		if quote.Error != nil || !quote.Owned || quote.PriceUnits != 0 {
			t.Fatalf("case edit lost ownership: %+v", quote)
		}
		lookup := AccountLookup_Resolve(server.Store.Database, t.Context(), "@MOON")
		if lookup.Error != nil || lookup.Value != user {
			t.Fatalf("case edit lost friend lookup: %+v", lookup)
		}
	}
}

const legacyAliasCases = `CREATE TABLE server_users(user_id_hash TEXT PRIMARY KEY,alias TEXT UNIQUE,created_at TEXT NOT NULL,payload TEXT NOT NULL);
INSERT INTO server_users VALUES('older','Shiori','2026-01-01T00:00:00Z','keep-old-data');
INSERT INTO server_users VALUES('newer','shiori','2026-02-01T00:00:00Z','keep-new-data');
INSERT INTO server_users VALUES('tie-old','NAME','2026-01-01T01:00:00Z','keep-tie-old');
INSERT INTO server_users VALUES('tie-new','name','2026-01-01T01:00:00Z','keep-tie-new');
INSERT INTO server_users VALUES('single','  MaPle  ','2026-01-01T00:00:00Z','keep-single');
INSERT INTO server_users VALUES('unicode','KITE','2026-01-01T00:00:00Z','keep-unicode');
CREATE TABLE private_progress(owner TEXT PRIMARY KEY REFERENCES server_users(user_id_hash) ON DELETE CASCADE,level INTEGER);
INSERT INTO private_progress VALUES('older',12),('newer',40);`

func TestAliasCaseMigrationKeepsOlderOwnershipAndAccounts(t *testing.T) {
	store := schemaFixture(t, legacyAliasCases)
	for pass := 0; pass < 2; pass++ {
		if err := AliasCase_Ensure(store.Database, t.Context()); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"older": "Shiori", "newer": "", "tie-old": "NAME", "tie-new": "", "single": "MaPle", "unicode": "KITE"}
		for owner, alias := range want {
			var got sql.NullString
			if err := store.Database.QueryRow("SELECT alias FROM server_users WHERE user_id_hash=?", owner).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got.String != alias {
				t.Fatalf("%s alias %q, want %q", owner, got.String, alias)
			}
		}
		var count int
		if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_users WHERE payload LIKE 'keep-%'").Scan(&count); err != nil || count != 6 {
			t.Fatal("accounts changed", count, err)
		}
		if err := store.Database.QueryRow("SELECT SUM(level) FROM private_progress").Scan(&count); err != nil || count != 52 {
			t.Fatal("progress changed", count, err)
		}
		if err := store.Database.QueryRow("SELECT COUNT(*) FROM server_alias_case_collisions").Scan(&count); err != nil || count != 2 {
			t.Fatal("collision recovery", count, err)
		}
	}
	for _, alias := range []string{"SHIORI", " ShIoRi "} {
		if _, err := store.Database.Exec("INSERT INTO server_users VALUES('duplicate',?,'2026-03-01','new')", alias); err == nil || !strings.Contains(err.Error(), "UNIQUE") {
			t.Fatalf("duplicate %q accepted: %v", alias, err)
		}
	}
	if _, err := store.Database.Exec("UPDATE server_users SET alias='PuRpLe' WHERE user_id_hash='newer'"); err != nil {
		t.Fatal(err)
	}
	if err := AliasCase_Ensure(store.Database, t.Context()); err != nil {
		t.Fatal(err)
	}
	var alias string
	if err := store.Database.QueryRow("SELECT alias FROM server_users WHERE user_id_hash='newer'").Scan(&alias); err != nil || alias != "PuRpLe" {
		t.Fatal("new claim", alias, err)
	}
}

func TestAliasCaseMigrationRollsBackOnFailure(t *testing.T) {
	store := schemaFixture(t, legacyAliasCases+"CREATE TABLE server_users_alias_case_unique(value TEXT);")
	if err := AliasCase_Ensure(store.Database, t.Context()); err == nil {
		t.Fatal("expected index failure")
	}
	var older, newer string
	if err := store.Database.QueryRow("SELECT alias FROM server_users WHERE user_id_hash='older'").Scan(&older); err != nil {
		t.Fatal(err)
	}
	if err := store.Database.QueryRow("SELECT alias FROM server_users WHERE user_id_hash='newer'").Scan(&newer); err != nil {
		t.Fatal(err)
	}
	if older != "Shiori" || newer != "shiori" {
		t.Fatal("failed migration changed aliases", older, newer)
	}
}
