package database_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nais/v0s/internal/database"
)

func TestSuppressionMatching(t *testing.T) {
	ctx := context.Background()
	const (
		columns = "INSERT INTO suppressions (team, image_name, package_key, vulnerability_id, state, detail, updated_by) VALUES "
		// Team a's suppression of lodash in repo/app, which both teams' images are named.
		teamA = columns + "('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');"
		teamB = columns + "('team-b', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');"
		// Team b also uses team a's image sha256:a.
		shared       = "INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES ('c1', 'team-b', 'shared', 'repo/app:1', 1);"
		sharedLodash = "team-b/shared CVE-1 pkg:npm/lodash@4.17.20"
	)

	tests := []struct {
		name       string
		seed       string
		teams      []string
		suppressed []string
	}{
		// Not team b's lodash: it has the same image name, package and vulnerability, but is team b's.
		{name: "active", seed: teamA, suppressed: []string{appLodash, workerLodash}},
		{name: "another team's suppression", seed: teamA, teams: []string{"team-b"}},
		// A suppression is keyed on the package, not the version, so team b's covers 4.17.19.
		{name: "each team its own", seed: teamA + teamB, suppressed: []string{appLodash, workerLodash, otherLodash}},
		{name: "other image name", seed: columns + "('team-a', 'repo/old', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me')"},
		{name: "other package", seed: columns + "('team-a', 'repo/app', 'pkg:npm/express', 'CVE-1', 'accepted_risk', 'd', 'me')"},
		// Team b uses sha256:a too and has not suppressed it.
		{name: "shared image, one team", seed: teamA + shared, suppressed: []string{appLodash, workerLodash}},
		{name: "shared image, both teams", seed: teamA + teamB + shared, suppressed: []string{appLodash, workerLodash, otherLodash, sharedLodash}},
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
			for _, f := range only {
				if s := f.Suppression; s == nil || s.Team != f.Workload.Team || s.Package != f.Finding.PackageKey || s.VulnerabilityID != f.Finding.VulnerabilityID {
					t.Errorf("finding %s/%s %s: suppression %+v, want its team's", f.Workload.Team, f.Workload.Name, f.Finding.PURL, s)
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
				if f.Suppression != nil {
					t.Errorf("unsuppressed finding %s has suppression %+v", f.Finding.PURL, f.Suppression)
				}
			}
		})
	}
}

func TestCountFindingsSuppression(t *testing.T) {
	db, exec := newFixture(t)
	// Team a suppresses lodash in repo/app, and team b also uses team a's sha256:a.
	exec(`INSERT INTO suppressions (team, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');
		INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES ('c1', 'team-b', 'shared', 'repo/app:1', 1);`)

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

var lodashKey = database.SuppressionKey{ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityID: "CVE-1"}

func lodashSuppression(state string) database.NewSuppression {
	return database.NewSuppression{SuppressionKey: lodashKey, State: state, Detail: "not used"}
}

// set sets team-a's suppressions as me.
func set(t *testing.T, db *database.DB, items ...database.NewSuppression) []database.Suppression {
	t.Helper()
	set, err := db.SetSuppressions(context.Background(), "team-a", items, "me")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// listSuppressions returns every suppression.
func listSuppressions(t *testing.T, db *database.DB) []database.Suppression {
	t.Helper()
	all, _, err := db.ListSuppressions(context.Background(), database.SuppressionFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	return all
}

func TestSetSuppressions(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves alias and normalizes package", func(t *testing.T) {
		db, _ := newFixture(t)
		item := lodashSuppression("accepted_risk")
		item.Package = "pkg:npm/lodash@4.17.20?arch=x"
		item.VulnerabilityID = "GHSA-1"
		s := set(t, db, item)[0]
		if s.Team != "team-a" || s.SuppressionKey != lodashKey || s.UpdatedBy != "me" || s.UpdatedAt.IsZero() {
			t.Errorf("set = %+v, want team-a's CVE-1 on pkg:npm/lodash by me", s)
		}
		listed, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{VulnerabilityID: "GHSA-1"}, database.Page{})
		if err != nil || len(listed) != 1 || listed[0] != s {
			t.Errorf("ListSuppressions by alias = %+v, %v; want %+v", listed, err, s)
		}
	})

	// GHSA-1 names CVE-1 as an alias and a stale record of its own, and
	// ListFindings by GHSA-1 matches both, so a suppression for it is ambiguous.
	t.Run("rejects ID that is also an alias", func(t *testing.T) {
		db, exec := newFixture(t)
		exec(`INSERT INTO vulnerabilities (id, db_version) VALUES ('GHSA-1', now())`)
		item := lodashSuppression("accepted_risk")
		item.VulnerabilityID = "GHSA-1"
		if _, err := db.SetSuppressions(ctx, "team-a", []database.NewSuppression{item}, "me"); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("SetSuppressions: err = %v, want ErrInvalid", err)
		}
	})

	t.Run("replaces the team's suppression", func(t *testing.T) {
		db, _ := newFixture(t)
		first := lodashSuppression("accepted_risk")
		set(t, db, first)
		second := lodashSuppression("false_positive")
		second.Detail = "scanner is wrong"
		if _, err := db.SetSuppressions(ctx, "team-a", []database.NewSuppression{second}, "you"); err != nil {
			t.Fatal(err)
		}
		all := listSuppressions(t, db)
		if len(all) != 1 || all[0].State != "false_positive" || all[0].Detail != "scanner is wrong" || all[0].UpdatedBy != "you" {
			t.Errorf("suppressions = %+v, want one, false_positive by you", all)
		}
	})

	t.Run("replaces only the team's own suppression", func(t *testing.T) {
		db, _ := newFixture(t)
		set(t, db, lodashSuppression("accepted_risk"))
		if _, err := db.SetSuppressions(ctx, "team-b", []database.NewSuppression{lodashSuppression("false_positive")}, "me"); err != nil {
			t.Fatal(err)
		}
		all := listSuppressions(t, db)
		if len(all) != 2 || all[0].Team != "team-a" || all[0].State != "accepted_risk" || all[1].Team != "team-b" {
			t.Errorf("suppressions = %+v, want team-a's accepted_risk and team-b's", all)
		}
	})

	t.Run("all or nothing", func(t *testing.T) {
		db, _ := newFixture(t)
		bad := lodashSuppression("accepted_risk")
		bad.VulnerabilityID = "CVE-404"
		_, err := db.SetSuppressions(ctx, "team-a", []database.NewSuppression{lodashSuppression("accepted_risk"), bad}, "me")
		if !errors.Is(err, database.ErrInvalid) || !strings.Contains(err.Error(), "suppression 1") {
			t.Errorf("err = %v, want ErrInvalid naming suppression 1", err)
		}
		if all := listSuppressions(t, db); len(all) != 0 {
			t.Errorf("suppressions after failure = %+v, want none", all)
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
			{name: "no suppressions", team: "team-a", actor: "me"},
			{name: "missing image name", team: "team-a", items: with(func(s *database.NewSuppression) { s.ImageName = "" }), actor: "me"},
			{name: "ambiguous alias", team: "team-a", items: with(func(s *database.NewSuppression) { s.VulnerabilityID = "GHSA-2" }), actor: "me"},
			{name: "not a purl", team: "team-a", items: with(func(s *database.NewSuppression) { s.Package = "lodash" }), actor: "me"},
			{name: "unknown state", team: "team-a", items: with(func(s *database.NewSuppression) { s.State = "" }), actor: "me"},
			{name: "empty detail", team: "team-a", items: with(func(s *database.NewSuppression) { s.Detail = "" }), actor: "me"},
			{name: "duplicate key via alias", team: "team-a", items: append(with(func(*database.NewSuppression) {}), with(func(s *database.NewSuppression) { s.VulnerabilityID = "GHSA-1" })...), actor: "me"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := db.SetSuppressions(ctx, tt.team, tt.items, tt.actor); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("err = %v, want ErrInvalid", err)
				}
			})
		}
	})
}

func TestDeleteSuppressions(t *testing.T) {
	ctx := context.Background()
	db, _ := newFixture(t)
	set(t, db, lodashSuppression("accepted_risk"))
	// The same key, given as a purl with version and an alias.
	key := database.SuppressionKey{ImageName: "repo/app", Package: "pkg:npm/lodash@4.17.20", VulnerabilityID: "GHSA-1"}

	if deleted, err := db.DeleteSuppressions(ctx, "team-b", []database.SuppressionKey{key}); err != nil || len(deleted) != 0 {
		t.Errorf("deleting as another team = %+v, %v; want nothing deleted", deleted, err)
	}
	ambiguous := key
	ambiguous.VulnerabilityID = "GHSA-2"
	if _, err := db.DeleteSuppressions(ctx, "team-a", []database.SuppressionKey{key, ambiguous}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("deleting with an ambiguous key: err = %v, want ErrInvalid", err)
	}
	if all := listSuppressions(t, db); len(all) != 1 {
		t.Fatalf("suppressions after failed deletes = %+v, want the one kept", all)
	}

	deleted, err := db.DeleteSuppressions(ctx, "team-a", []database.SuppressionKey{key})
	if err != nil || len(deleted) != 1 || deleted[0].SuppressionKey != lodashKey {
		t.Errorf("deleting = %+v, %v; want the suppression of %+v", deleted, err, lodashKey)
	}
	if all := listSuppressions(t, db); len(all) != 0 {
		t.Errorf("suppressions after deleting = %+v, want none", all)
	}
	if deleted, err := db.DeleteSuppressions(ctx, "team-a", []database.SuppressionKey{key}); err != nil || len(deleted) != 0 {
		t.Errorf("deleting again = %+v, %v; want nothing deleted and no error", deleted, err)
	}
}

func TestListSuppressionsPagination(t *testing.T) {
	ctx := context.Background()
	db, _ := newFixture(t)
	express := lodashSuppression("accepted_risk")
	express.Package = "pkg:npm/express"
	express.VulnerabilityID = "CVE-2"
	set(t, db, lodashSuppression("accepted_risk"), express)
	if _, err := db.SetSuppressions(ctx, "team-b", []database.NewSuppression{lodashSuppression("accepted_risk")}, "me"); err != nil {
		t.Fatal(err)
	}

	var (
		got  []string
		page = database.Page{Size: 1}
	)
	for range 10 {
		suppressions, next, err := db.ListSuppressions(ctx, database.SuppressionFilter{}, page)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range suppressions {
			got = append(got, s.Team+" "+s.Package)
		}
		if next == "" {
			break
		}
		page.Token = next
	}
	want := []string{"team-a pkg:npm/express", "team-a pkg:npm/lodash", "team-b pkg:npm/lodash"}
	if !slices.Equal(got, want) {
		t.Errorf("suppressions = %q, want %q", got, want)
	}
}
