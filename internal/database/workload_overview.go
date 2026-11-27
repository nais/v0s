package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type VulnerabilitySeverityCounts struct {
	Critical int64
	High     int64
	Medium   int64
	Low      int64
	Unknown  int64
}

type WorkloadFindingCounts struct {
	FindingCount                int64
	UniqueVulnerabilityCount    int64
	SeverityCounts              VulnerabilitySeverityCounts
	UniqueKEVVulnerabilityCount int64
}

type WorkloadOverview struct {
	Workload Workload
	Counts   WorkloadFindingCounts
}

type WorkloadOverviewList struct {
	Workloads     []WorkloadOverview
	NextPageToken string
	TotalCount    int64
}

const workloadOverviewCursorVersion = 2
const workloadOverviewOperation = "workload-overview"

func (db *DB) ListWorkloadOverview(ctx context.Context, selection WorkloadFilter, page Page, filter FindingFilter) (WorkloadOverviewList, error) {
	filter, err := normalizeUnscopedFindingFilter(filter)
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	selection, err = selection.normalized()
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	binding, err := queryBinding(filter, selection)
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	var cursor workloadCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("invalid workload overview cursor; restart pagination without a token: %w", err)
	}
	if page.Token != "" &&
		(cursor.Version != workloadOverviewCursorVersion || cursor.Operation != workloadOverviewOperation || cursor.Binding != binding ||
			cursor.Environment == "" || cursor.Team == "" || cursor.Name == "") {
		return WorkloadOverviewList{}, fmt.Errorf("invalid workload overview cursor or changed scope/filters; restart pagination without a token: %w", ErrInvalid)
	}
	var args sqlArgs
	selected := and(selection.conditions(&args))
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := requireKEVCatalog(ctx, tx); err != nil {
		return WorkloadOverviewList{}, err
	}
	var result WorkloadOverviewList
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM workloads w WHERE `+selected, args...).Scan(&result.TotalCount); err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("counting workload overview: %w", err)
	}
	filter.Teams, filter.Environment, filter.Workload = selection.Teams, selection.Environment, selection.Workload
	filter.Selector = selection.Selector
	where, err := filter.conditions(&args)
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	rank := severityRank("f.severity")
	query := `WITH selected AS (
		SELECT w.* FROM workloads w WHERE ` + selected + `
	), per_vulnerability AS (
		SELECT w.environment, w.team, w.name, f.vulnerability_id,
			count(*) AS findings, max(` + rank + `) AS severity_rank, bool_or(k.cve IS NOT NULL) AS kev
		FROM ` + findingsFrom + `
		LEFT JOIN kev k ON k.cve = f.vulnerability_id
		WHERE ` + and(where) + `
		GROUP BY w.environment, w.team, w.name, f.vulnerability_id
	), counts AS (
		SELECT environment, team, name, sum(findings)::bigint AS finding_count,
			count(*) AS unique_count, count(*) FILTER (WHERE kev) AS kev_count,
			count(*) FILTER (WHERE severity_rank = 4) AS critical,
			count(*) FILTER (WHERE severity_rank = 3) AS high,
			count(*) FILTER (WHERE severity_rank = 2) AS medium,
			count(*) FILTER (WHERE severity_rank = 1) AS low,
			count(*) FILTER (WHERE severity_rank = 0) AS unknown
		FROM per_vulnerability GROUP BY environment, team, name
	), overview AS (
		SELECT w.*, coalesce(c.finding_count, 0) AS finding_count,
			coalesce(c.unique_count, 0) AS unique_count, coalesce(c.kev_count, 0) AS kev_count,
			coalesce(c.critical, 0) AS critical, coalesce(c.high, 0) AS high,
			coalesce(c.medium, 0) AS medium, coalesce(c.low, 0) AS low,
			coalesce(c.unknown, 0) AS unknown
		FROM selected w LEFT JOIN counts c USING (environment, team, name)
	) `
	seek := "true"
	if page.Token != "" {
		seek = fmt.Sprintf("(w.environment, w.team, w.name) > (%s, %s, %s)",
			args.add(cursor.Environment), args.add(cursor.Team), args.add(cursor.Name))
	}
	limit := page.limit()
	rows, err := tx.Query(ctx, query+`
		SELECT w.environment, w.team, w.name, w.image_reference, w.resolve_error, `+imageColumns+`,
			w.finding_count, w.unique_count, w.kev_count, w.critical, w.high, w.medium, w.low, w.unknown
		FROM overview w LEFT JOIN images i ON i.id = w.image_id
		WHERE `+seek+` ORDER BY w.environment, w.team, w.name LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("listing workload overview: %w", err)
	}
	result.Workloads, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (WorkloadOverview, error) {
		var v WorkloadOverview
		var img imageScan
		w, c := &v.Workload, &v.Counts
		dest := []any{&w.Environment, &w.Team, &w.Name, &w.ImageReference, &w.ResolveError}
		dest = append(dest, img.dest()...)
		dest = append(dest, &c.FindingCount, &c.UniqueVulnerabilityCount, &c.UniqueKEVVulnerabilityCount,
			&c.SeverityCounts.Critical, &c.SeverityCounts.High, &c.SeverityCounts.Medium, &c.SeverityCounts.Low, &c.SeverityCounts.Unknown)
		if err := row.Scan(dest...); err != nil {
			return WorkloadOverview{}, err
		}
		if img.found() {
			image := img.image()
			w.Image = &image
		}
		return v, nil
	})
	if err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("listing workload overview: %w", err)
	}
	if len(result.Workloads) > limit {
		result.Workloads = result.Workloads[:limit]
		last := result.Workloads[limit-1].Workload
		result.NextPageToken, err = encodePageToken(workloadCursor{
			Version: workloadOverviewCursorVersion, Operation: workloadOverviewOperation, Binding: binding,
			Environment: last.Environment, Team: last.Team, Name: last.Name,
		})
		if err != nil {
			return WorkloadOverviewList{}, err
		}
	}
	return result, nil
}
