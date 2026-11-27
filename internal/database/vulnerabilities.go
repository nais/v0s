package database

import (
	"context"
	"fmt"
	"slices"

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
	PageInfo        PageInfo
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
	if c.Version != order.cursorVersion() || c.Operation != "vulnerabilities" {
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

func (o VulnerabilityOrder) cursorVersion() int {
	if o.Field == VulnerabilityOrderSeverity && o.Direction == FindingOrderASC {
		return 2
	}
	return 1
}

func (o VulnerabilityOrder) keyset() keysetOrder {
	id := keysetTerm{column: `id COLLATE "C"`}
	desc := o.Direction == FindingOrderDESC
	switch o.Field {
	case VulnerabilityOrderSeverity:
		return keysetOrder{{severityRank("severity"), desc}, id}
	case VulnerabilityOrderWorkloads:
		return keysetOrder{{"workloads", desc}, id}
	default:
		id.desc = desc
		return keysetOrder{id}
	}
}

func (c vulnerabilityCursor) values(o VulnerabilityOrder) []any {
	switch o.Field {
	case VulnerabilityOrderSeverity:
		return []any{severityValue(c.Severity), c.ID}
	case VulnerabilityOrderWorkloads:
		return []any{*c.Workloads, c.ID}
	default:
		return []any{c.ID}
	}
}

func (db *DB) ListVulnerabilities(ctx context.Context, filter FindingFilter, page Page, order VulnerabilityOrder) (VulnerabilityList, error) {
	if err := page.validate(); err != nil {
		return VulnerabilityList{}, err
	}
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
	rank := severityRank("f.severity")
	grouped := `WITH grouped AS (
		SELECT f.vulnerability_id AS id,
			CASE max(` + rank + `) WHEN 4 THEN 'CRITICAL' WHEN 3 THEN 'HIGH'
				WHEN 2 THEN 'MEDIUM' WHEN 1 THEN 'LOW' ELSE 'UNKNOWN' END AS severity,
			count(*) AS findings, count(DISTINCT (w.environment, w.team, w.name)) AS workloads
		FROM ` + findingsFrom + ` WHERE ` + and(where) + `
		GROUP BY f.vulnerability_id
	) `
	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VulnerabilityList{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if filter.OnlyKnownExploited {
		if err := requireKEVCatalog(ctx, tx); err != nil {
			return VulnerabilityList{}, err
		}
	}
	var result VulnerabilityList
	if err := tx.QueryRow(ctx, grouped+`SELECT count(*) FROM grouped`, args...).Scan(&result.TotalCount); err != nil {
		return VulnerabilityList{}, fmt.Errorf("counting vulnerabilities: %w", err)
	}
	countArgs := slices.Clone(args)
	searchOrder := order.keyset()
	seek := "true"
	if page.Token != "" {
		seek = searchOrder.seek(cursor.values(order), &args, page.Direction == PageBackward, false)
	}
	rows, err := tx.Query(ctx, grouped+`SELECT id, severity, findings, workloads FROM grouped WHERE `+seek+
		` ORDER BY `+searchOrder.sql(page.Direction == PageBackward)+` LIMIT `+args.add(page.limit()+1), args...)
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
	if page.Direction == PageBackward {
		slices.Reverse(result.Vulnerabilities)
	}
	for _, v := range result.Vulnerabilities {
		token, err := encodePageToken(newVulnerabilityCursor(v, binding, order))
		if err != nil {
			return VulnerabilityList{}, err
		}
		result.Cursors = append(result.Cursors, token)
	}
	var edge []any
	if len(result.Vulnerabilities) > 0 {
		index := 0
		if page.Direction == PageBackward {
			index = len(result.Vulnerabilities) - 1
		}
		edge = newVulnerabilityCursor(result.Vulnerabilities[index], binding, order).values(order)
	} else if page.Token != "" {
		edge = cursor.values(order)
	}
	result.PageInfo, err = keysetPageInfo(ctx, tx, grouped+"SELECT EXISTS (SELECT 1 FROM grouped WHERE ",
		countArgs, searchOrder, page, edge, len(result.Vulnerabilities) == 0, hasNext)
	if err != nil {
		return VulnerabilityList{}, err
	}
	if result.PageInfo.HasNextPage && len(result.Cursors) > 0 {
		result.NextPageToken = result.Cursors[len(result.Cursors)-1]
	}
	return result, nil
}

func newVulnerabilityCursor(v VulnerabilitySummary, binding string, order VulnerabilityOrder) vulnerabilityCursor {
	c := vulnerabilityCursor{Version: order.cursorVersion(), Operation: "vulnerabilities", Binding: binding, ID: v.VulnerabilityID}
	if order.Field == VulnerabilityOrderSeverity {
		c.Severity = v.Severity
	}
	if order.Field == VulnerabilityOrderWorkloads {
		c.Workloads = &v.AffectedWorkloadCount
	}
	return c
}
