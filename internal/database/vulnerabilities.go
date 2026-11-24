package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/v0s"
)

type VulnerabilityOrder struct {
	Field     VulnerabilityOrderField
	Direction FindingOrderDirection
}

type VulnerabilityOrderField int

const (
	VulnerabilityOrderSeverity VulnerabilityOrderField = iota + 1
	VulnerabilityOrderID
	VulnerabilityOrderWorkloads
)

func (o VulnerabilityOrder) effective() (VulnerabilityOrder, error) {
	if o == (VulnerabilityOrder{}) {
		return VulnerabilityOrder{Field: VulnerabilityOrderSeverity, Direction: FindingOrderDESC}, nil
	}
	if o.Field < VulnerabilityOrderSeverity || o.Field > VulnerabilityOrderWorkloads ||
		(o.Direction != FindingOrderASC && o.Direction != FindingOrderDESC) {
		return VulnerabilityOrder{}, fmt.Errorf("invalid vulnerability order: %w", ErrInvalid)
	}
	return o, nil
}

type VulnerabilitySummary struct {
	VulnerabilityID       string
	Severity              v0s.Severity
	FindingCount          int64
	AffectedWorkloadCount int64
}

type VulnerabilityList struct {
	Vulnerabilities []VulnerabilitySummary
	NextPageToken   string
	Cursors         []string
	TotalCount      int64
}

type vulnerabilityCursor struct {
	Version   int          `json:"version"`
	Operation string       `json:"operation"`
	Binding   string       `json:"binding"`
	ID        string       `json:"id"`
	Severity  v0s.Severity `json:"severity,omitempty"`
	Workloads *int64       `json:"workloads,omitempty"`
}

func (c vulnerabilityCursor) validate(binding string, order VulnerabilityOrder) error {
	if c.Version != 1 || c.Operation != "vulnerabilities" {
		return fmt.Errorf("incompatible vulnerability cursor; restart pagination without a token: %w", ErrInvalid)
	}
	if c.Binding != binding {
		return fmt.Errorf("vulnerability cursor filter or order changed; restart pagination without a token: %w", ErrInvalid)
	}
	if c.ID == "" {
		return fmt.Errorf("incomplete vulnerability cursor; restart pagination without a token: %w", ErrInvalid)
	}
	if order.Field == VulnerabilityOrderSeverity {
		switch c.Severity {
		case v0s.SeverityUnknown, v0s.SeverityLow, v0s.SeverityMedium, v0s.SeverityHigh, v0s.SeverityCritical:
		default:
			return fmt.Errorf("invalid vulnerability cursor severity; restart pagination without a token: %w", ErrInvalid)
		}
	}
	if order.Field == VulnerabilityOrderWorkloads && (c.Workloads == nil || *c.Workloads <= 0) {
		return fmt.Errorf("invalid vulnerability cursor workload count; restart pagination without a token: %w", ErrInvalid)
	}
	return nil
}

func (o VulnerabilityOrder) sql() string {
	switch o.Field {
	case VulnerabilityOrderSeverity:
		return (FindingOrder{Direction: o.Direction}).severityRank("severity") + `, id COLLATE "C"`
	case VulnerabilityOrderWorkloads:
		direction := "ASC"
		if o.Direction == FindingOrderDESC {
			direction = "DESC"
		}
		return "workloads " + direction + `, id COLLATE "C"`
	default:
		if o.Direction == FindingOrderDESC {
			return `id COLLATE "C" DESC`
		}
		return `id COLLATE "C"`
	}
}

func (o VulnerabilityOrder) after(c vulnerabilityCursor, args *sqlArgs) string {
	id := args.add(c.ID)
	op := ">"
	if o.Direction == FindingOrderDESC {
		op = "<"
	}
	switch o.Field {
	case VulnerabilityOrderSeverity:
		rank := FindingOrder{Direction: o.Direction}
		return fmt.Sprintf(`(%s, id COLLATE "C") > (%s, %s::text COLLATE "C")`,
			rank.severityRank("severity"), rank.severityRank(args.add(string(c.Severity))+"::text"), id)
	case VulnerabilityOrderWorkloads:
		count := args.add(*c.Workloads)
		return fmt.Sprintf(`(workloads %s %s OR (workloads = %s AND id COLLATE "C" > %s::text COLLATE "C"))`, op, count, count, id)
	default:
		return fmt.Sprintf(`id COLLATE "C" %s %s::text COLLATE "C"`, op, id)
	}
}

func (db *DB) ListVulnerabilities(ctx context.Context, filter FindingFilter, page Page, order VulnerabilityOrder) (VulnerabilityList, error) {
	order, err := order.effective()
	if err != nil {
		return VulnerabilityList{}, err
	}
	filter, err = normalizeFindingFilter(filter)
	if err != nil {
		return VulnerabilityList{}, err
	}
	binding, err := queryBinding(filter, order)
	if err != nil {
		return VulnerabilityList{}, err
	}
	var cursor vulnerabilityCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return VulnerabilityList{}, fmt.Errorf("invalid vulnerability cursor; restart pagination without a token: %w", err)
	}
	if page.Token != "" {
		if err := cursor.validate(binding, order); err != nil {
			return VulnerabilityList{}, err
		}
	}
	var args sqlArgs
	where, err := filter.conditions(&args)
	if err != nil {
		return VulnerabilityList{}, err
	}
	if filter.OnlyKnownExploited {
		if err := db.requireKEVCatalog(ctx); err != nil {
			return VulnerabilityList{}, err
		}
	}
	rank := (FindingOrder{Direction: FindingOrderDESC}).severityRank("f.severity")
	grouped := `WITH grouped AS (
		SELECT f.vulnerability_id AS id,
			CASE min(` + rank + `) WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH'
				WHEN 2 THEN 'MEDIUM' WHEN 3 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
			count(*) AS findings, count(DISTINCT (w.environment, w.team, w.name)) AS workloads
		FROM ` + findingsFrom + ` WHERE ` + and(where) + `
		GROUP BY f.vulnerability_id
	) `
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VulnerabilityList{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var result VulnerabilityList
	if err := tx.QueryRow(ctx, grouped+`SELECT count(*) FROM grouped`, args...).Scan(&result.TotalCount); err != nil {
		return VulnerabilityList{}, fmt.Errorf("counting vulnerabilities: %w", err)
	}
	seek := "true"
	if page.Token != "" {
		seek = order.after(cursor, &args)
	}
	rows, err := tx.Query(ctx, grouped+`SELECT id, severity, findings, workloads FROM grouped WHERE `+seek+
		` ORDER BY `+order.sql()+` LIMIT `+args.add(page.limit()+1), args...)
	if err != nil {
		return VulnerabilityList{}, fmt.Errorf("listing vulnerabilities: %w", err)
	}
	result.Vulnerabilities, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (VulnerabilitySummary, error) {
		var v VulnerabilitySummary
		err := row.Scan(&v.VulnerabilityID, &v.Severity, &v.FindingCount, &v.AffectedWorkloadCount)
		return v, err
	})
	if err != nil {
		return VulnerabilityList{}, fmt.Errorf("listing vulnerabilities: %w", err)
	}
	hasNext := len(result.Vulnerabilities) > page.limit()
	if hasNext {
		result.Vulnerabilities = result.Vulnerabilities[:page.limit()]
	}
	for _, v := range result.Vulnerabilities {
		c := vulnerabilityCursor{Version: 1, Operation: "vulnerabilities", Binding: binding, ID: v.VulnerabilityID}
		if order.Field == VulnerabilityOrderSeverity {
			c.Severity = v.Severity
		}
		if order.Field == VulnerabilityOrderWorkloads {
			c.Workloads = &v.AffectedWorkloadCount
		}
		token, err := encodePageToken(c)
		if err != nil {
			return VulnerabilityList{}, err
		}
		result.Cursors = append(result.Cursors, token)
	}
	if hasNext {
		result.NextPageToken = result.Cursors[len(result.Cursors)-1]
	}
	return result, nil
}
