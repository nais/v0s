package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type WorkloadOrderField int

const (
	WorkloadOrderIdentity WorkloadOrderField = iota + 1
	WorkloadOrderFindingCount
)

type WorkloadOrder struct {
	Field     WorkloadOrderField
	Direction FindingOrderDirection
}

func (o WorkloadOrder) effective() (WorkloadOrder, error) {
	if o == (WorkloadOrder{}) {
		return WorkloadOrder{Field: WorkloadOrderIdentity, Direction: FindingOrderASC}, nil
	}
	if (o.Field == WorkloadOrderIdentity && o.Direction == FindingOrderASC) ||
		(o.Field == WorkloadOrderFindingCount && (o.Direction == FindingOrderASC || o.Direction == FindingOrderDESC)) {
		return o, nil
	}
	return WorkloadOrder{}, fmt.Errorf("invalid workload order: %w", ErrInvalid)
}

type WorkloadOverviewOptions struct {
	FindingFilter FindingFilter
	AffectedOnly  bool
	Order         WorkloadOrder
}

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
	Cursors       []string
	TotalCount    int64
}

type workloadOverviewCursor struct {
	Version      int    `json:"version"`
	Operation    string `json:"operation"`
	Binding      string `json:"binding"`
	Environment  string `json:"environment"`
	Team         string `json:"team"`
	Name         string `json:"name"`
	FindingCount *int64 `json:"finding_count,omitempty"`
}

func (c workloadOverviewCursor) validate(binding string, order WorkloadOrder) error {
	if c.Version != 1 || c.Operation != "workload-overview" {
		return fmt.Errorf("incompatible workload overview cursor; restart pagination without a token: %w", ErrInvalid)
	}
	if c.Binding != binding {
		return fmt.Errorf("workload overview cursor parameters changed; restart pagination without a token: %w", ErrInvalid)
	}
	if c.Environment == "" || c.Team == "" || c.Name == "" ||
		(order.Field == WorkloadOrderFindingCount && (c.FindingCount == nil || *c.FindingCount < 0)) {
		return fmt.Errorf("incomplete or invalid workload overview cursor; restart pagination without a token: %w", ErrInvalid)
	}
	return nil
}

func (o WorkloadOrder) sql() string {
	if o.Field == WorkloadOrderFindingCount {
		if o.Direction == FindingOrderDESC {
			return "w.finding_count DESC, w.environment, w.team, w.name"
		}
		return "w.finding_count ASC, w.environment, w.team, w.name"
	}
	return "w.environment, w.team, w.name"
}

func (o WorkloadOrder) after(c workloadOverviewCursor, args *sqlArgs) string {
	identity := fmt.Sprintf("(w.environment, w.team, w.name) > (%s, %s, %s)",
		args.add(c.Environment), args.add(c.Team), args.add(c.Name))
	if o.Field != WorkloadOrderFindingCount {
		return identity
	}
	count := args.add(*c.FindingCount)
	op := ">"
	if o.Direction == FindingOrderDESC {
		op = "<"
	}
	return fmt.Sprintf("(w.finding_count %s %s OR (w.finding_count = %s AND %s))", op, count, count, identity)
}

func (db *DB) ListWorkloadOverview(ctx context.Context, selection WorkloadFilter, page Page, options WorkloadOverviewOptions) (WorkloadOverviewList, error) {
	order, err := options.Order.effective()
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	options.Order = order
	filter, err := normalizeUnscopedFindingFilter(options.FindingFilter)
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	selection, err = selection.normalized()
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	binding, err := queryBinding(filter, struct {
		Selection    WorkloadFilter
		AffectedOnly bool
		Order        WorkloadOrder
	}{selection, options.AffectedOnly, order})
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	var cursor workloadOverviewCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("invalid workload overview cursor; restart pagination without a token: %w", err)
	}
	if page.Token != "" {
		if err := cursor.validate(binding, order); err != nil {
			return WorkloadOverviewList{}, err
		}
	}
	var args sqlArgs
	selected := and(selection.conditions(&args))
	filter.Teams, filter.Environment, filter.Workload = selection.Teams, selection.Environment, selection.Workload
	filter.Selector = selection.Selector
	where, err := filter.conditions(&args)
	if err != nil {
		return WorkloadOverviewList{}, err
	}
	affected := "true"
	if options.AffectedOnly {
		affected = "c.finding_count > 0"
	}
	rank := (FindingOrder{Direction: FindingOrderDESC}).severityRank("f.severity")
	query := `WITH selected AS (
		SELECT w.* FROM workloads w WHERE ` + selected + `
	), per_vulnerability AS (
		SELECT w.environment, w.team, w.name, f.vulnerability_id,
			count(*) AS findings, min(` + rank + `) AS severity_rank, bool_or(k.cve IS NOT NULL) AS kev
		FROM ` + findingsFrom + `
		LEFT JOIN kev k ON k.cve = f.vulnerability_id
		WHERE ` + and(where) + `
		GROUP BY w.environment, w.team, w.name, f.vulnerability_id
	), counts AS (
		SELECT environment, team, name, sum(findings)::bigint AS finding_count,
			count(*) AS unique_count, count(*) FILTER (WHERE kev) AS kev_count,
			count(*) FILTER (WHERE severity_rank = 0) AS critical,
			count(*) FILTER (WHERE severity_rank = 1) AS high,
			count(*) FILTER (WHERE severity_rank = 2) AS medium,
			count(*) FILTER (WHERE severity_rank = 3) AS low,
			count(*) FILTER (WHERE severity_rank = 4) AS unknown
		FROM per_vulnerability GROUP BY environment, team, name
	), overview AS (
		SELECT w.*, coalesce(c.finding_count, 0) AS finding_count,
			coalesce(c.unique_count, 0) AS unique_count, coalesce(c.kev_count, 0) AS kev_count,
			coalesce(c.critical, 0) AS critical, coalesce(c.high, 0) AS high,
			coalesce(c.medium, 0) AS medium, coalesce(c.low, 0) AS low,
			coalesce(c.unknown, 0) AS unknown
		FROM selected w LEFT JOIN counts c USING (environment, team, name)
		WHERE ` + affected + `
	) `
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := requireKEVCatalog(ctx, tx); err != nil {
		return WorkloadOverviewList{}, err
	}
	var result WorkloadOverviewList
	if err := tx.QueryRow(ctx, query+`SELECT count(*) FROM overview`, args...).Scan(&result.TotalCount); err != nil {
		return WorkloadOverviewList{}, fmt.Errorf("counting workload overview: %w", err)
	}
	seek := "true"
	if page.Token != "" {
		seek = order.after(cursor, &args)
	}
	rows, err := tx.Query(ctx, query+`
		SELECT w.environment, w.team, w.name, w.image_reference, w.resolve_error, `+imageColumns+`,
			w.finding_count, w.unique_count, w.kev_count, w.critical, w.high, w.medium, w.low, w.unknown
		FROM overview w LEFT JOIN images i ON i.id = w.image_id
		WHERE `+seek+` ORDER BY `+order.sql()+` LIMIT `+args.add(page.limit()+1), args...)
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
	hasNext := len(result.Workloads) > page.limit()
	if hasNext {
		result.Workloads = result.Workloads[:page.limit()]
	}
	for _, v := range result.Workloads {
		c := workloadOverviewCursor{Version: 1, Operation: "workload-overview", Binding: binding,
			Environment: v.Workload.Environment, Team: v.Workload.Team, Name: v.Workload.Name}
		if order.Field == WorkloadOrderFindingCount {
			c.FindingCount = &v.Counts.FindingCount
		}
		token, err := encodePageToken(c)
		if err != nil {
			return WorkloadOverviewList{}, err
		}
		result.Cursors = append(result.Cursors, token)
	}
	if hasNext {
		result.NextPageToken = result.Cursors[len(result.Cursors)-1]
	}
	return result, nil
}
