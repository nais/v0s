package database_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database"
)

func TestSuppressionMatching(t *testing.T) {
	ctx := context.Background()
	const (
		columns = "INSERT INTO suppressions (team, image_name, package_key, vulnerability_id, state, detail, created_by, created_at, expires_at, revoked_at, revoked_by) VALUES "
		// Team a's suppression of lodash in repo/app, which both teams' images are named.
		teamA = columns + "('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now(), NULL, NULL, '');"
		teamB = columns + "('team-b', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now(), NULL, NULL, '');"
		// Team b also uses team a's image sha256:a.
		shared = "INSERT INTO workload_images (environment, team, workload, image_id) VALUES ('c1', 'team-b', 'shared', 1);"
	)

	tests := []struct {
		name  string
		seed  string
		teams []string
		// suppressed are the suppressed findings, and suppressedBy the teams whose
		// suppressions each of them lists.
		suppressed   []string
		suppressedBy [][]string
	}{
		// Only sha256:a: team b's lodash in sha256:b has the same image name, package and vulnerability.
		{name: "active", seed: teamA, suppressed: []string{aLodash}, suppressedBy: [][]string{{"team-a"}}},
		{name: "another team's suppression", seed: teamA, teams: []string{"team-b"}},
		// The suppression covers both lodash versions: it is keyed on the package, not the version.
		{name: "every version", seed: teamA + teamB, suppressed: []string{aLodash, bLodash}, suppressedBy: [][]string{{"team-a"}, {"team-b"}}},
		{name: "active until expiry", seed: columns + "('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now(), now() + interval '1 hour', NULL, '')",
			suppressed: []string{aLodash}, suppressedBy: [][]string{{"team-a"}}},
		{name: "expired", seed: columns + "('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now() - interval '2 hours', now() - interval '1 hour', NULL, '')"},
		{name: "revoked", seed: columns + "('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now(), NULL, now(), 'you')"},
		{name: "other image name", seed: columns + "('team-a', 'repo/old', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now(), NULL, NULL, '')"},
		{name: "other package", seed: columns + "('team-a', 'repo/app', 'pkg:npm/express', 'CVE-1', 'accepted_risk', 'd', 'me', now(), NULL, NULL, '')"},
		// Team b uses sha256:a too and has not suppressed it.
		{name: "shared image, one team", seed: teamA + shared},
		{name: "shared image, the suppressing team", seed: teamA + shared, teams: []string{"team-a"},
			suppressed: []string{aLodash}, suppressedBy: [][]string{{"team-a"}}},
		{name: "shared image, both teams", seed: teamA + teamB + shared,
			suppressed: []string{aLodash, bLodash}, suppressedBy: [][]string{{"team-a", "team-b"}, {"team-b"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, exec := newFixture(t)
			exec(tt.seed)

			only, _, err := db.ListFindings(ctx, database.FindingFilter{Teams: tt.teams, Suppressed: database.SuppressedOnly}, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			if got := findingKeys(only); !slices.Equal(got, tt.suppressed) {
				t.Errorf("suppressed findings = %q, want %q", got, tt.suppressed)
			}
			for i, f := range only {
				var teams []string
				for _, s := range f.Suppressions {
					teams = append(teams, s.Team)
				}
				if !f.Suppressed || i >= len(tt.suppressedBy) || !slices.Equal(teams, tt.suppressedBy[i]) {
					t.Errorf("finding %s: suppressed %v by %q, want suppressed by %q", f.Finding.PURL, f.Suppressed, teams, tt.suppressedBy)
				}
			}

			excluded, _, err := db.ListFindings(ctx, database.FindingFilter{Teams: tt.teams}, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			all, _, err := db.ListFindings(ctx, database.FindingFilter{Teams: tt.teams, Suppressed: database.SuppressedInclude}, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			if len(excluded)+len(only) != len(all) || slices.ContainsFunc(findingKeys(excluded), func(k string) bool { return slices.Contains(tt.suppressed, k) }) {
				t.Errorf("unsuppressed findings = %q, want the other findings of %q", findingKeys(excluded), findingKeys(all))
			}
			for _, f := range excluded {
				if f.Suppressed {
					t.Errorf("unsuppressed finding %s is marked suppressed", f.Finding.PURL)
				}
			}
		})
	}
}

func TestCountFindingsPerTeamSuppression(t *testing.T) {
	db, exec := newFixture(t)
	// Team a suppresses lodash in repo/app, and team b also uses team a's sha256:a.
	exec(`INSERT INTO suppressions (team, image_name, package_key, vulnerability_id, state, detail, created_by)
		VALUES ('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');
		INSERT INTO workload_images (environment, team, workload, image_id) VALUES ('c1', 'team-b', 'shared', 1);`)

	got, err := db.CountFindings(context.Background(), database.FindingFilter{}, database.GroupByTeam)
	if err != nil {
		t.Fatal(err)
	}
	// Team a: express in its two workloads. Team b: lodash in sha256:b, and lodash and express in sha256:a.
	want := []database.FindingCount{{Key: "team-a", Count: 2}, {Key: "team-b", Count: 3}}
	if !slices.Equal(got, want) {
		t.Errorf("CountFindings by team = %v, want %v", got, want)
	}
}

func lodashSuppression(state string) database.NewSuppression {
	return database.NewSuppression{ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityID: "CVE-1", State: state, Detail: "not used"}
}

func TestCreateSuppressions(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves alias and normalizes package", func(t *testing.T) {
		db, _ := newFixture(t)
		item := lodashSuppression("accepted_risk")
		item.Package = "pkg:npm/lodash@4.17.20?arch=x"
		item.VulnerabilityID = "GHSA-1"
		created, err := db.CreateSuppressions(ctx, "team-a", []database.NewSuppression{item}, "me", false)
		if err != nil {
			t.Fatal(err)
		}
		c := created[0]
		// Only lodash in sha256:a: team b's sha256:b has the same image name but is not team a's.
		if c.Suppression.ID == 0 || c.Suppression.Team != "team-a" || c.Suppression.VulnerabilityID != "CVE-1" || c.Suppression.PackageKey != "pkg:npm/lodash" || c.MatchedFindings != 1 || c.ReplacesID != 0 {
			t.Errorf("created = %+v, want team-a's CVE-1 on pkg:npm/lodash matching 1 finding", c)
		}
		listed, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{VulnerabilityID: "GHSA-1"}, database.Page{})
		if err != nil || len(listed) != 1 || listed[0].ID != c.Suppression.ID {
			t.Errorf("ListSuppressions by alias = %+v, %v; want the created suppression", listed, err)
		}
	})

	// GHSA-1 names CVE-1 as an alias and a stale record of its own, and
	// ListFindings by GHSA-1 matches both, so a suppression for it is ambiguous.
	t.Run("rejects ID that is also an alias", func(t *testing.T) {
		db, exec := newFixture(t)
		exec(`INSERT INTO vulnerabilities (id) VALUES ('GHSA-1')`)
		item := lodashSuppression("accepted_risk")
		item.VulnerabilityID = "GHSA-1"
		if _, err := db.CreateSuppressions(ctx, "team-a", []database.NewSuppression{item}, "me", false); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("CreateSuppressions: err = %v, want ErrInvalid", err)
		}
		if _, err := db.GetVulnerability(ctx, "GHSA-1"); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("GetVulnerability: err = %v, want ErrInvalid", err)
		}
	})

	t.Run("replaces active suppression", func(t *testing.T) {
		db, _ := newFixture(t)
		first := create(t, db, lodashSuppression("accepted_risk"))
		second := create(t, db, lodashSuppression("false_positive"))
		if second.ReplacesID != first.Suppression.ID {
			t.Errorf("replaces ID = %d, want %d", second.ReplacesID, first.Suppression.ID)
		}
		old := suppression(t, db, first.Suppression.ID)
		if old.RevokedAt.IsZero() || old.RevokedBy != "me" || old.RevokeReason != "replaced by suppression "+strconv.FormatInt(second.Suppression.ID, 10) {
			t.Errorf("replaced suppression = %+v, want revoked by me, replaced by %d", old, second.Suppression.ID)
		}
	})

	t.Run("replaces only the team's own suppression", func(t *testing.T) {
		db, _ := newFixture(t)
		first := create(t, db, lodashSuppression("accepted_risk"))
		created, err := db.CreateSuppressions(ctx, "team-b", []database.NewSuppression{lodashSuppression("false_positive")}, "me", false)
		if err != nil {
			t.Fatal(err)
		}
		if created[0].ReplacesID != 0 || created[0].MatchedFindings != 1 {
			t.Errorf("team-b's suppression = %+v, want replacing nothing, matching 1", created[0])
		}
		if old := suppression(t, db, first.Suppression.ID); !old.RevokedAt.IsZero() {
			t.Errorf("team-a's suppression = %+v, want it unrevoked", old)
		}
	})

	t.Run("revokes expired suppression", func(t *testing.T) {
		db, exec := newFixture(t)
		exec(`INSERT INTO suppressions (id, team, image_name, package_key, vulnerability_id, state, detail, created_by, created_at, expires_at)
			OVERRIDING SYSTEM VALUE VALUES (100, 'team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me', now() - interval '2 hours', now() - interval '1 hour')`)
		created := create(t, db, lodashSuppression("accepted_risk"))
		if created.ReplacesID != 0 {
			t.Errorf("replaces ID = %d, want 0 for an expired predecessor", created.ReplacesID)
		}
		if old := suppression(t, db, 100); old.RevokedAt.IsZero() || old.RevokeReason != "expired" {
			t.Errorf("expired suppression = %+v, want revoked as expired", old)
		}
	})

	t.Run("dry run writes nothing", func(t *testing.T) {
		db, _ := newFixture(t)
		first := create(t, db, lodashSuppression("accepted_risk"))
		results, err := db.CreateSuppressions(ctx, "team-a", []database.NewSuppression{lodashSuppression("false_positive")}, "me", true)
		if err != nil {
			t.Fatal(err)
		}
		if r := results[0]; r.Suppression.ID != 0 || r.ReplacesID != first.Suppression.ID || r.MatchedFindings != 1 {
			t.Errorf("dry run result = %+v, want ID 0, replacing %d, matching 1", r, first.Suppression.ID)
		}
		all, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{IncludeInactive: true}, database.Page{})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 1 || !all[0].RevokedAt.IsZero() {
			t.Errorf("suppressions after dry run = %+v, want only the first, unrevoked", all)
		}
	})

	t.Run("all or nothing", func(t *testing.T) {
		db, _ := newFixture(t)
		bad := lodashSuppression("accepted_risk")
		bad.VulnerabilityID = "CVE-404"
		_, err := db.CreateSuppressions(ctx, "team-a", []database.NewSuppression{lodashSuppression("accepted_risk"), bad}, "me", false)
		if !errors.Is(err, database.ErrInvalid) || !strings.Contains(err.Error(), "suppression 1") {
			t.Errorf("err = %v, want ErrInvalid naming suppression 1", err)
		}
		all, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{IncludeInactive: true}, database.Page{})
		if err != nil || len(all) != 0 {
			t.Errorf("suppressions after failure = %+v, %v; want none", all, err)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		db, _ := newFixture(t)
		with := func(f func(*database.NewSuppression)) []database.NewSuppression {
			s := lodashSuppression("accepted_risk")
			f(&s)
			return []database.NewSuppression{s}
		}
		tests := []struct {
			name  string
			team  string
			items []database.NewSuppression
			actor string
		}{
			{name: "missing team", items: with(func(*database.NewSuppression) {}), actor: "me"},
			{name: "missing actor", team: "team-a", items: with(func(*database.NewSuppression) {})},
			{name: "ambiguous alias", team: "team-a", items: with(func(s *database.NewSuppression) { s.VulnerabilityID = "GHSA-2" }), actor: "me"},
			{name: "not a purl", team: "team-a", items: with(func(s *database.NewSuppression) { s.Package = "lodash" }), actor: "me"},
			{name: "unknown state", team: "team-a", items: with(func(s *database.NewSuppression) { s.State = "" }), actor: "me"},
			{name: "not_affected without justification", team: "team-a", items: with(func(s *database.NewSuppression) { s.State = "not_affected" }), actor: "me"},
			{name: "justification on accepted_risk", team: "team-a", items: with(func(s *database.NewSuppression) { s.Justification = "code_not_present" }), actor: "me"},
			{name: "empty detail", team: "team-a", items: with(func(s *database.NewSuppression) { s.Detail = "" }), actor: "me"},
			{name: "expiry in the past", team: "team-a", items: with(func(s *database.NewSuppression) { s.ExpiresAt = time.Now().Add(-time.Minute) }), actor: "me"},
			{name: "duplicate key via alias", team: "team-a", items: append(with(func(*database.NewSuppression) {}), with(func(s *database.NewSuppression) { s.VulnerabilityID = "GHSA-1" })...), actor: "me"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := db.CreateSuppressions(ctx, tt.team, tt.items, tt.actor, false); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("err = %v, want ErrInvalid", err)
				}
			})
		}
	})
}

func TestRevokeSuppressions(t *testing.T) {
	ctx := context.Background()
	db, _ := newFixture(t)
	id := create(t, db, lodashSuppression("accepted_risk")).Suppression.ID

	if _, err := db.RevokeSuppressions(ctx, "team-a", []int64{id, 404}, "me", "fixed"); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("revoking unknown ID: err = %v, want ErrNotFound", err)
	}
	if _, err := db.RevokeSuppressions(ctx, "team-b", []int64{id}, "me", "fixed"); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("revoking another team's suppression: err = %v, want ErrNotFound", err)
	}
	if s := suppression(t, db, id); !s.RevokedAt.IsZero() {
		t.Fatalf("suppression %d revoked by a failed request", id)
	}

	revoked, err := db.RevokeSuppressions(ctx, "team-a", []int64{id}, "me", "fixed")
	if err != nil {
		t.Fatal(err)
	}
	if r := revoked[0]; r.RevokedAt.IsZero() || r.RevokedBy != "me" || r.RevokeReason != "fixed" {
		t.Errorf("revoked = %+v, want revoked by me for fixed", r)
	}
	if _, err := db.RevokeSuppressions(ctx, "team-a", []int64{id}, "me", "fixed"); !errors.Is(err, database.ErrAlreadyRevoked) {
		t.Errorf("revoking twice: err = %v, want ErrAlreadyRevoked", err)
	}
	active, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{}, database.Page{})
	if err != nil || len(active) != 0 {
		t.Errorf("active suppressions = %+v, %v; want none", active, err)
	}
}

func create(t *testing.T, db *database.DB, s database.NewSuppression) database.CreatedSuppression {
	t.Helper()
	created, err := db.CreateSuppressions(context.Background(), "team-a", []database.NewSuppression{s}, "me", false)
	if err != nil {
		t.Fatal(err)
	}
	return created[0]
}

// suppression returns the suppression with id, active or not.
func suppression(t *testing.T, db *database.DB, id int64) database.Suppression {
	t.Helper()
	all, _, err := db.ListSuppressions(context.Background(), database.SuppressionFilter{IncludeInactive: true}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("suppression %d not found", id)
	return database.Suppression{}
}
