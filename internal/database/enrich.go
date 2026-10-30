package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s"
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

// replaceTable replaces the contents of table with rows in one transaction. Rows are copied into
// a temporary table first, so readers see the old contents until commit. table must be a
// constant table name.
func (db *DB) replaceTable(ctx context.Context, table string, columns []string, rows [][]any) error {
	staging := "new_" + table
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s (LIKE %s INCLUDING ALL) ON COMMIT DROP`, staging, table)); err != nil {
			return fmt.Errorf("creating staging table: %w", err)
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{staging}, columns, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("copying rows: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s`, table)); err != nil {
			return fmt.Errorf("deleting rows: %w", err)
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s SELECT * FROM %s`, table, staging)); err != nil {
			return fmt.Errorf("inserting rows: %w", err)
		}
		return nil
	})
}
