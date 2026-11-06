package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s/internal/v0s"
)

// ReplaceEPSS atomically replaces the EPSS scores.
func (db *DB) ReplaceEPSS(ctx context.Context, scores []v0s.EPSS) error {
	rows := make([][]any, len(scores))
	for i, s := range scores {
		rows[i] = []any{s.CVE, s.Score, s.Percentile, s.Date}
	}
	if err := db.replaceTable(ctx, "epss", []string{"cve", "score", "percentile", "date"}, rows); err != nil {
		return fmt.Errorf("replacing epss: %w", err)
	}
	return nil
}

// ReplaceKEV atomically replaces the CISA KEV entries.
func (db *DB) ReplaceKEV(ctx context.Context, entries []v0s.KEV) error {
	rows := make([][]any, len(entries))
	for i, e := range entries {
		dueDate := pgtype.Date{Time: e.DueDate, Valid: !e.DueDate.IsZero()}
		rows[i] = []any{e.CVE, e.DateAdded, dueDate, e.KnownRansomwareCampaign}
	}
	if err := db.replaceTable(ctx, "kev", []string{"cve", "date_added", "due_date", "known_ransomware_campaign"}, rows); err != nil {
		return fmt.Errorf("replacing kev: %w", err)
	}
	return nil
}

// replaceTable replaces the contents of table with rows in one transaction. Readers see the old
// contents until commit. table must be a constant table name.
func (db *DB) replaceTable(ctx context.Context, table string, columns []string, rows [][]any) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table); err != nil {
			return fmt.Errorf("deleting rows: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{table}, columns, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("copying rows: %w", err)
		}
		return nil
	})
}
