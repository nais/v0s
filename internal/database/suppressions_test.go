package database_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestSuppressionMatching(t *testing.T) {
	ctx := context.Background()
	const (
		columns = "INSERT INTO suppressions (environment, workload, team, image_name, package_key, vulnerability_id, state, detail, updated_by) VALUES "
		teamA   = columns + "('c1', 'app', 'team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');"
		teamB   = columns + "('c1', 'other', 'team-b', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');"
		// Team b also uses team a's image sha256:a.
		shared = "INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES ('c1', 'team-b', 'shared', 'repo/app:1', 1);"
	)

	tests := []struct {
		name       string
		seed       string
		teams      []string
		suppressed []string
	}{
		// Not team b's lodash: it has the same image name, package and vulnerability, but is team b's.
		{name: "only selected workload", seed: teamA, suppressed: []string{appLodash}},
		{name: "another team's suppression", seed: teamA, teams: []string{"team-b"}},
		// A suppression is keyed on the package, not the version, so team b's covers 4.17.19.
		{name: "each workload its own", seed: teamA + teamB, suppressed: []string{appLodash, otherLodash}},
		{name: "other image name", seed: columns + "('c1', 'app', 'team-a', 'repo/old', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me')"},
		{name: "other package", seed: columns + "('c1', 'app', 'team-a', 'repo/app', 'pkg:npm/express', 'CVE-1', 'accepted_risk', 'd', 'me')"},
		// Team b uses sha256:a too and has not suppressed it.
		{name: "shared image, one team", seed: teamA + shared, suppressed: []string{appLodash}},
		{name: "shared image, both teams", seed: teamA + teamB + shared, suppressed: []string{appLodash, otherLodash}},
		{name: "same workload name, other environment", seed: teamA + "INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES ('c2', 'team-a', 'app', 'repo/app:1', 1);", suppressed: []string{appLodash}},
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
				if s := f.Suppression; s == nil || s.Team != f.Workload.Team || s.Environment != f.Workload.Environment || s.Workload != f.Workload.Name || s.Package != f.Finding.PackageKey || s.VulnerabilityID != f.Finding.VulnerabilityID {
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
			if len(excluded)+len(only) != len(all) {
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
	exec(`INSERT INTO suppressions (environment, workload, team, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('c1', 'app', 'team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'd', 'me');
		INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES ('c1', 'team-b', 'shared', 'repo/app:1', 1);`)

	got, err := db.CountFindings(context.Background(), database.FindingFilter{}, database.GroupByTeam)
	if err != nil {
		t.Fatal(err)
	}
	// Team a: app's express and both worker findings. Team b's findings are unchanged.
	want := []database.FindingCount{{Key: "team-a", Count: 3}, {Key: "team-b", Count: 3}}
	if !slices.Equal(got, want) {
		t.Errorf("CountFindings by team = %v, want %v", got, want)
	}
}

var lodashKey = database.SuppressionKey{Environment: "c1", Workload: "app", ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityID: "CVE-1"}

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
			{name: "missing environment", team: "team-a", items: with(func(s *database.NewSuppression) { s.Environment = "" }), actor: "me"},
			{name: "missing workload", team: "team-a", items: with(func(s *database.NewSuppression) { s.Workload = "" }), actor: "me"},
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
	key := lodashKey
	key.Package, key.VulnerabilityID = "pkg:npm/lodash@4.17.20", "GHSA-1"

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
	worker := lodashSuppression("not_affected")
	worker.Workload = "worker"
	prod := lodashSuppression("accepted_risk")
	prod.Environment = "prod"
	set(t, db, worker, prod)
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
			got = append(got, s.Team+" "+s.Environment+" "+s.Workload+" "+s.Package)
		}
		if next == "" {
			break
		}
		page.Token = next
	}
	want := []string{"team-a c1 app pkg:npm/express", "team-a c1 app pkg:npm/lodash", "team-a c1 worker pkg:npm/lodash", "team-a prod app pkg:npm/lodash", "team-b c1 app pkg:npm/lodash"}
	if !slices.Equal(got, want) {
		t.Errorf("suppressions = %q, want %q", got, want)
	}
}

func TestWorkloadSuppressionBatch(t *testing.T) {
	db, exec := newFixture(t)
	ctx := context.Background()
	set(t, db, lodashSuppression("not_affected"))

	// Discovery includes already assessed findings, without restricting the image.
	filter := database.FindingFilter{Teams: []string{"team-a"}, VulnerabilityIDs: []string{"GHSA-1"}, Package: "pkg:npm/lodash", Suppressed: database.SuppressedInclude}
	findings, _, err := db.ListFindings(ctx, filter, database.Page{})
	if err != nil || len(findings) != 2 {
		t.Fatalf("discover workloads = %v, %v; want app and worker", findings, err)
	}
	var selected []database.NewSuppression
	for _, f := range findings {
		selected = append(selected, database.NewSuppression{
			Environment: f.Workload.Environment, Workload: f.Workload.Name, ImageName: f.Image.Name, Package: f.Finding.PackageKey, VulnerabilityID: f.Finding.VulnerabilityID,
			State: "accepted_risk", Detail: "explicitly selected",
		})
	}
	set(t, db, selected...)
	if _, err := db.DeleteSuppressions(ctx, "team-a", []database.SuppressionKey{lodashKey}); err != nil {
		t.Fatal(err)
	}
	only, _, err := db.ListFindings(ctx, database.FindingFilter{Suppressed: database.SuppressedOnly}, database.Page{})
	if err != nil || !slices.Equal(findingKeys(only), []string{workerLodash}) {
		t.Fatalf("after deleting app assessment = %v, %v; want worker only", findingKeys(only), err)
	}
	listed, _, err := db.ListSuppressions(ctx, database.SuppressionFilter{Teams: []string{"team-a"}, Environment: "c1", Workload: "worker"}, database.Page{Size: 1})
	if err != nil || len(listed) != 1 || listed[0].Workload != "worker" {
		t.Fatalf("list worker assessments = %v, %v", listed, err)
	}
	// A new digest and package version in the same repository retain this workload's assessment.
	exec(`UPDATE workloads SET image_id = 2 WHERE team = 'team-a' AND name = 'worker'`)
	only, _, err = db.ListFindings(ctx, database.FindingFilter{Suppressed: database.SuppressedOnly}, database.Page{})
	if err != nil || len(only) != 1 || only[0].Workload.Name != "worker" || only[0].Image.Digest != "sha256:b" {
		t.Fatalf("after rebuild = %v, %v; want worker's new image assessed", only, err)
	}
	exec(`UPDATE workloads SET image_id = 3 WHERE team = 'team-a' AND name = 'worker'`)
	only, _, err = db.ListFindings(ctx, database.FindingFilter{Suppressed: database.SuppressedOnly}, database.Page{})
	if err != nil || len(only) != 0 {
		t.Fatalf("after repository change = %v, %v; want no inherited assessment", only, err)
	}
}

func TestMigrateWorkloadSuppressions(t *testing.T) {
	db, url := databasetest.NewWithURL(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Reconstruct the deployed v1 schema, then exercise the migration command's database path.
	_, err = conn.Exec(ctx, fixture+`
			ALTER TABLE vulnerabilities ADD COLUMN cvss jsonb NOT NULL DEFAULT '{}';
			UPDATE vulnerabilities SET cvss = '{"nvd":{"v3_score":7.5}}' WHERE id = 'CVE-1';
			DROP TABLE suppressions;
			ALTER TABLE legacy_suppressions RENAME TO suppressions;
			ALTER INDEX legacy_suppressions_pkey RENAME TO suppressions_pkey;
			DELETE FROM schema_migrations WHERE version > 1;
			INSERT INTO suppressions (team, image_name, package_key, vulnerability_id, state, detail, updated_by, updated_at)
			VALUES ('team-a', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'original reason', 'original actor', '2026-01-02'),
			       ('team-a', 'repo/absent', 'pkg:npm/lodash', 'CVE-1', 'not_affected', 'unmatched', 'me', '2026-01-02');
			INSERT INTO workloads (environment, team, name, image_reference, image_id)
			VALUES ('prod', 'team-a', 'app', 'repo/app:2', 2);
			INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
			VALUES ('prod', 'team-a', 'unresolved', 'repo/app:missing', 'not found');`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := database.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	migrated, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	var removed bool
	if err := conn.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'vulnerabilities' AND column_name = 'cvss'
	)`).Scan(&removed); err != nil || !removed {
		t.Fatalf("legacy score column removed = %t, %v", removed, err)
	}
	all := listSuppressions(t, migrated)
	if len(all) != 3 {
		t.Fatalf("migrated = %+v, want three current matching workloads", all)
	}
	for _, s := range all {
		if s.Team != "team-a" || s.Detail != "original reason" || s.UpdatedBy != "original actor" || s.UpdatedAt.Format("2006-01-02") != "2026-01-02" {
			t.Errorf("migration changed attribution or scope: %+v", s)
		}
	}
	var preserved int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM legacy_suppressions").Scan(&preserved); err != nil || preserved != 2 {
		t.Errorf("original assessments = %d, %v; want both preserved", preserved, err)
	}
	// Reopening does not reapply legacy assessments over subsequent edits or deletes.
	if _, err := migrated.DeleteSuppressions(ctx, "team-a", []database.SuppressionKey{lodashKey}); err != nil {
		t.Fatal(err)
	}
	migrated.Close()
	if err := database.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	reopened, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if all := listSuppressions(t, reopened); len(all) != 2 {
		t.Errorf("after restart = %+v, want deleted assessment to stay deleted", all)
	}
}
