package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database"
)

var forwardedAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func forwardedAssessment() *database.V13sAssessment {
	return &database.V13sAssessment{State: "accepted_risk", Detail: "assessed in v13s", UpdatedBy: "v13s-user", UpdatedAt: forwardedAt}
}

func forwardedLodash(ids ...string) database.V13sSuppression {
	return database.V13sSuppression{
		ImageName:        "repo/app",
		Package:          "pkg:npm/lodash@4.17.20?arch=x#sub",
		VulnerabilityIDs: ids,
		Assessment:       forwardedAssessment(),
	}
}

func apply(t *testing.T, db *database.DB, s database.V13sSuppression) database.ForwardResult {
	t.Helper()
	result, err := db.ApplyV13sSuppression(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func suppressionKeys(ss []database.Suppression) []string {
	keys := make([]string, 0, len(ss))
	for _, s := range ss {
		keys = append(keys, s.Team+"/"+s.Environment+"/"+s.Workload+" "+s.ImageName+" "+s.Package+" "+s.VulnerabilityID)
	}
	return keys
}

func TestApplyV13sSuppressionFansOutToImageName(t *testing.T) {
	db, exec := newFixture(t)
	exec(`INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
		VALUES ('c2', 'team-c', 'unresolved', 'repo/app:3', 'not found')`)

	result := apply(t, db, forwardedLodash("GHSA-1"))
	if result != (database.ForwardResult{Outcome: database.ForwardApplied, Applied: 3}) {
		t.Fatalf("result = %+v, want 3 applied", result)
	}
	all := listSuppressions(t, db)
	want := []string{
		"team-a/c1/app repo/app pkg:npm/lodash CVE-1",
		"team-a/c1/worker repo/app pkg:npm/lodash CVE-1",
		"team-b/c1/other repo/app pkg:npm/lodash CVE-1",
	}
	if got := suppressionKeys(all); !slices.Equal(got, want) {
		t.Fatalf("suppressions = %q, want %q", got, want)
	}
	for _, s := range all {
		if s.State != "accepted_risk" || s.Detail != "assessed in v13s" || s.UpdatedBy != "v13s-user" || !s.UpdatedAt.Equal(forwardedAt) {
			t.Errorf("suppression %+v, want the forwarded assessment, actor and time", s)
		}
	}
}

func TestApplyV13sSuppressionWithoutFinding(t *testing.T) {
	db, _ := newFixture(t)
	s := forwardedLodash("CVE-3")
	s.Package = "pkg:npm/express"
	if result := apply(t, db, s); result.Outcome != database.ForwardApplied || result.Applied != 3 {
		t.Fatalf("result = %+v, want 3 applied without an active finding", result)
	}
}

func TestApplyV13sSuppressionRepeatUpdateAndDelete(t *testing.T) {
	db, exec := newFixture(t)
	exec(`INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team-a', 'c1', 'app', 'repo/app', 'pkg:npm/express', 'CVE-2', 'not_affected', 'unrelated', 'someone'),
			('team-a', 'c1', 'app', 'repo/old', 'pkg:npm/lodash', 'CVE-1', 'not_affected', 'other image', 'someone')`)

	apply(t, db, forwardedLodash("CVE-1"))
	if result := apply(t, db, forwardedLodash("CVE-1", "GHSA-1")); result != (database.ForwardResult{Outcome: database.ForwardApplied}) {
		t.Errorf("repeat = %+v, want nothing applied", result)
	}

	edited := forwardedLodash("CVE-1")
	edited.Assessment.State, edited.Assessment.Detail = "false_positive", "not reachable"
	edited.Assessment.UpdatedAt = forwardedAt.Add(time.Hour)
	if result := apply(t, db, edited); result.Applied != 3 {
		t.Errorf("edit = %+v, want 3 applied", result)
	}
	for _, s := range listSuppressions(t, db) {
		if s.VulnerabilityID == "CVE-1" && s.ImageName == "repo/app" && (s.State != "false_positive" || !s.UpdatedAt.Equal(edited.Assessment.UpdatedAt)) {
			t.Errorf("after edit %+v, want false_positive at the edited time", s)
		}
	}

	unsuppressed := forwardedLodash("GHSA-1")
	unsuppressed.Assessment = nil
	if result := apply(t, db, unsuppressed); result != (database.ForwardResult{Outcome: database.ForwardApplied, Removed: 3}) {
		t.Errorf("delete = %+v, want 3 removed", result)
	}
	want := []string{
		"team-a/c1/app repo/app pkg:npm/express CVE-2",
		"team-a/c1/app repo/old pkg:npm/lodash CVE-1",
	}
	if got := suppressionKeys(listSuppressions(t, db)); !slices.Equal(got, want) {
		t.Errorf("after delete = %q, want only the unrelated suppressions %q", got, want)
	}
	if result := apply(t, db, unsuppressed); result != (database.ForwardResult{Outcome: database.ForwardApplied}) {
		t.Errorf("repeated delete = %+v, want nothing removed", result)
	}
}

func TestApplyV13sSuppressionBlocked(t *testing.T) {
	db, _ := newFixture(t)
	unknown := forwardedLodash("CVE-404")
	ambiguousAlias := forwardedLodash("GHSA-2")
	ambiguousIDs := forwardedLodash("CVE-1", "CVE-2")
	noWorkloads := forwardedLodash("CVE-1")
	noWorkloads.ImageName = "repo/old"
	for _, blocked := range []blockedForward{
		{name: "unknown", suppression: unknown, want: database.ForwardUnknownVulnerability},
		{name: "ambiguous alias", suppression: ambiguousAlias, want: database.ForwardAmbiguousVulnerability},
		{name: "ambiguous IDs", suppression: ambiguousIDs, want: database.ForwardAmbiguousVulnerability},
		{name: "no workloads", suppression: noWorkloads, want: database.ForwardNoWorkloads},
	} {
		t.Run(blocked.name, func(t *testing.T) {
			if result := apply(t, db, blocked.suppression); result != (database.ForwardResult{Outcome: blocked.want}) {
				t.Errorf("result = %+v, want outcome %d with no changes", result, blocked.want)
			}
		})
	}
	if all := listSuppressions(t, db); len(all) != 0 {
		t.Errorf("suppressions = %+v, want none", all)
	}
	var vulnerabilities, aliases int
	if err := db.Pool().QueryRow(context.Background(), `SELECT (SELECT count(*) FROM vulnerabilities), (SELECT count(*) FROM vulnerability_aliases)`).Scan(&vulnerabilities, &aliases); err != nil {
		t.Fatal(err)
	}
	if vulnerabilities != 3 || aliases != 3 {
		t.Errorf("catalog has %d vulnerabilities and %d aliases, want the fixture's 3 and 3", vulnerabilities, aliases)
	}

	known := forwardedLodash("CVE-404", "CVE-1")
	if result := apply(t, db, known); result.Outcome != database.ForwardApplied || result.Applied != 3 {
		t.Errorf("unknown alias with a known ID = %+v, want 3 applied", result)
	}
}

type blockedForward struct {
	name        string
	suppression database.V13sSuppression
	want        database.ForwardOutcome
}

func TestApplyV13sSuppressionInvalid(t *testing.T) {
	db, _ := newFixture(t)
	for _, invalid := range []invalidForward{
		{name: "image name", change: func(s *database.V13sSuppression) { s.ImageName = "" }},
		{name: "package", change: func(s *database.V13sSuppression) { s.Package = "lodash" }},
		{name: "no IDs", change: func(s *database.V13sSuppression) { s.VulnerabilityIDs = nil }},
		{name: "empty ID", change: func(s *database.V13sSuppression) { s.VulnerabilityIDs = []string{"CVE-1", ""} }},
		{name: "state", change: func(s *database.V13sSuppression) { s.Assessment.State = "in_triage" }},
		{name: "detail", change: func(s *database.V13sSuppression) { s.Assessment.Detail = "" }},
		{name: "actor", change: func(s *database.V13sSuppression) { s.Assessment.UpdatedBy = "" }},
		{name: "update time", change: func(s *database.V13sSuppression) { s.Assessment.UpdatedAt = time.Time{} }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			s := forwardedLodash("CVE-1")
			invalid.change(&s)
			if _, err := db.ApplyV13sSuppression(context.Background(), s); !errors.Is(err, database.ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
	if all := listSuppressions(t, db); len(all) != 0 {
		t.Errorf("suppressions = %+v, want none", all)
	}
}

type invalidForward struct {
	name   string
	change func(*database.V13sSuppression)
}
