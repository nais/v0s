package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type Summary struct {
	FindingCount                int64
	UniqueVulnerabilityCount    int64
	AffectedWorkloadCount       int64
	SeverityCounts              VulnerabilitySeverityCounts
	UniqueKEVVulnerabilityCount int64
	KEVAffectedWorkloadCount    int64
	Coverage                    WorkloadCoverage
}

type WorkloadCoverage struct {
	TotalWorkloadCount   int64
	ScannedCount         int64
	PendingCount         int64
	NoSBOMCount          int64
	FailedCount          int64
	UnresolvedImageCount int64
}

func (db *DB) GetSummary(ctx context.Context, selection WorkloadFilter, filter FindingFilter) (Summary, error) {
	selection, err := selection.normalized()
	if err != nil {
		return Summary{}, err
	}
	filter, err = normalizeUnscopedFindingFilter(filter)
	if err != nil {
		return Summary{}, err
	}
	var args sqlArgs
	selected := and(selection.conditions(&args))
	filter.Teams, filter.Environment, filter.Workload = selection.Teams, selection.Environment, selection.Workload
	filter.Selector = selection.Selector
	where, err := filter.conditions(&args)
	if err != nil {
		return Summary{}, err
	}
	rank := severityRank("f.severity")
	query := `WITH selected AS (
		SELECT CASE
			WHEN i.id IS NULL THEN 'unresolved'
			WHEN i.sbom_state = 'missing' THEN 'no_sbom'
			WHEN i.sbom_state = 'failed' THEN 'failed'
			WHEN i.sbom_state <> 'fetched' THEN 'pending'
			WHEN i.scanned_at IS NOT NULL THEN 'scanned'
			WHEN i.error <> '' THEN 'failed'
			ELSE 'pending' END AS status
		FROM workloads w LEFT JOIN images i ON i.id = w.image_id
		WHERE ` + selected + `
	), matching AS (
		SELECT w.environment, w.team, w.name, f.vulnerability_id,
			` + rank + ` AS severity_rank, k.cve IS NOT NULL AS kev
		FROM ` + findingsFrom + ` LEFT JOIN kev k ON k.cve = f.vulnerability_id
		WHERE ` + and(where) + `
	), per_vulnerability AS (
		SELECT vulnerability_id, count(*) AS findings, max(severity_rank) AS severity_rank,
			bool_or(kev) AS kev
		FROM matching GROUP BY vulnerability_id
	), finding_totals AS (
		SELECT coalesce(sum(findings), 0)::bigint AS finding_count, count(*) AS unique_count,
			count(*) FILTER (WHERE kev) AS kev_count,
			count(*) FILTER (WHERE severity_rank = 4) AS critical,
			count(*) FILTER (WHERE severity_rank = 3) AS high,
			count(*) FILTER (WHERE severity_rank = 2) AS medium,
			count(*) FILTER (WHERE severity_rank = 1) AS low,
			count(*) FILTER (WHERE severity_rank = 0) AS unknown
		FROM per_vulnerability
	), workload_totals AS (
		SELECT count(DISTINCT (environment, team, name)) AS affected_count,
			count(DISTINCT (environment, team, name)) FILTER (WHERE kev) AS kev_affected_count
		FROM matching
	), coverage AS (
		SELECT count(*) AS total,
			count(*) FILTER (WHERE status = 'scanned') AS scanned,
			count(*) FILTER (WHERE status = 'pending') AS pending,
			count(*) FILTER (WHERE status = 'no_sbom') AS no_sbom,
			count(*) FILTER (WHERE status = 'failed') AS failed,
			count(*) FILTER (WHERE status = 'unresolved') AS unresolved
		FROM selected
	)
	SELECT finding_count, unique_count, affected_count, critical, high, medium, low, unknown,
		kev_count, kev_affected_count, total, scanned, pending, no_sbom, failed, unresolved
	FROM finding_totals CROSS JOIN workload_totals CROSS JOIN coverage`
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Summary{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := requireKEVCatalog(ctx, tx); err != nil {
		return Summary{}, err
	}
	var result Summary
	s, c := &result.SeverityCounts, &result.Coverage
	if err := tx.QueryRow(ctx, query, args...).Scan(
		&result.FindingCount, &result.UniqueVulnerabilityCount, &result.AffectedWorkloadCount,
		&s.Critical, &s.High, &s.Medium, &s.Low, &s.Unknown,
		&result.UniqueKEVVulnerabilityCount, &result.KEVAffectedWorkloadCount,
		&c.TotalWorkloadCount, &c.ScannedCount, &c.PendingCount, &c.NoSBOMCount, &c.FailedCount, &c.UnresolvedImageCount,
	); err != nil {
		return Summary{}, fmt.Errorf("reading summary: %w", err)
	}
	return result, nil
}
