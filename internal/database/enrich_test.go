package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
)

func TestReplaceEPSS(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	day := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	steps := []struct {
		name    string
		scores  []v0s.EPSS
		wantErr bool
		want    []string
	}{
		{
			name:   "initial",
			scores: []v0s.EPSS{{CVE: "CVE-1", Score: 0.1, Percentile: 0.5, Date: day}, {CVE: "CVE-2", Score: 0.2, Percentile: 0.6, Date: day}},
			want:   []string{"CVE-1 0.1 0.5 2026-03-01", "CVE-2 0.2 0.6 2026-03-01"},
		},
		{
			name:   "replaced",
			scores: []v0s.EPSS{{CVE: "CVE-2", Score: 0.3, Percentile: 0.7, Date: day}, {CVE: "CVE-3", Score: 0.4, Percentile: 0.8, Date: day}},
			want:   []string{"CVE-2 0.3 0.7 2026-03-01", "CVE-3 0.4 0.8 2026-03-01"},
		},
		{
			name:    "failure keeps previous contents",
			scores:  []v0s.EPSS{{CVE: "CVE-4", Date: day}, {CVE: "CVE-4", Date: day}},
			wantErr: true,
			want:    []string{"CVE-2 0.3 0.7 2026-03-01", "CVE-3 0.4 0.8 2026-03-01"},
		},
	}
	for _, s := range steps {
		err := db.ReplaceEPSS(ctx, s.scores)
		if s.wantErr != (err != nil) {
			t.Errorf("%s: err = %v, want error: %t", s.name, err, s.wantErr)
		}
		got := queryStrings(t, db, `SELECT concat_ws(' ', cve, score, percentile, date) FROM epss ORDER BY cve`)
		if !slices.Equal(got, s.want) {
			t.Errorf("%s: epss = %q, want %q", s.name, got, s.want)
		}
	}
}

func TestReplaceKEV(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	added := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	for _, entries := range [][]v0s.KEV{
		{{CVE: "CVE-1", DateAdded: added}},
		{{CVE: "CVE-2", DateAdded: added, DueDate: added.AddDate(0, 0, 21), KnownRansomwareCampaign: true}, {CVE: "CVE-3", DateAdded: added}},
	} {
		if err := db.ReplaceKEV(ctx, entries); err != nil {
			t.Fatal(err)
		}
	}
	got := queryStrings(t, db, `
		SELECT concat_ws(' ', cve, date_added, coalesce(due_date::text, 'none'), known_ransomware_campaign) FROM kev ORDER BY cve`)
	want := []string{"CVE-2 2026-03-01 2026-03-22 t", "CVE-3 2026-03-01 none f"}
	if !slices.Equal(got, want) {
		t.Errorf("kev = %q, want %q", got, want)
	}

	for _, entries := range [][]v0s.KEV{
		nil,
		{{CVE: "CVE-4", DateAdded: added}, {CVE: "CVE-4", DateAdded: added}},
	} {
		if err := db.ReplaceKEV(ctx, entries); err == nil {
			t.Fatal("invalid replacement succeeded")
		}
		got := queryStrings(t, db, `
			SELECT concat_ws(' ', cve, date_added, coalesce(due_date::text, 'none'), known_ransomware_campaign) FROM kev ORDER BY cve`)
		if !slices.Equal(got, want) {
			t.Errorf("failed refresh changed catalog: %q, want %q", got, want)
		}
	}
}

func TestKEVCatalogAvailability(t *testing.T) {
	db, exec := newFixture(t)
	exec(`DELETE FROM kev`)
	ctx := t.Context()
	if _, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{}); !errors.Is(err, database.ErrUnavailable) {
		t.Errorf("findings without catalog: %v, want ErrUnavailable", err)
	}
	if _, err := db.GetVulnerability(ctx, "CVE-1"); !errors.Is(err, database.ErrUnavailable) {
		t.Errorf("advisory without catalog: %v, want ErrUnavailable", err)
	}
	if _, err := db.CountFindings(ctx, database.FindingFilter{OnlyKnownExploited: true}, database.GroupBySeverity); !errors.Is(err, database.ErrUnavailable) {
		t.Errorf("KEV count without catalog: %v, want ErrUnavailable", err)
	}
	if _, err := db.CountFindings(ctx, database.FindingFilter{}, database.GroupBySeverity); err != nil {
		t.Errorf("ordinary count depends on KEV: %v", err)
	}
	if err := db.ReplaceKEV(ctx, []v0s.KEV{{CVE: "CVE-1", DateAdded: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	findings, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.KnownExploited != (f.Finding.VulnerabilityID == "CVE-1") {
			t.Errorf("unexpected membership: %+v", f)
		}
	}
}
