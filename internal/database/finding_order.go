package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/nais/v0s/internal/purl"
	"github.com/nais/v0s/internal/v0s"
	"github.com/package-url/packageurl-go"
)

type FindingOrder struct {
	Field     FindingOrderField
	Direction FindingOrderDirection
}

type FindingOrderField int
type FindingOrderDirection int

const (
	FindingOrderDefault FindingOrderField = iota
	FindingOrderSeverity
	FindingOrderVulnerabilityID
)

const (
	FindingOrderASC FindingOrderDirection = iota + 1
	FindingOrderDESC
)

func (o FindingOrder) validate() error {
	if o == (FindingOrder{}) {
		return nil
	}
	if (o.Field != FindingOrderSeverity && o.Field != FindingOrderVulnerabilityID) ||
		(o.Direction != FindingOrderASC && o.Direction != FindingOrderDESC) {
		return fmt.Errorf("invalid finding order: %w", ErrInvalid)
	}
	return nil
}

func normalizedSet[S ~[]E, E ~string](values S) S {
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}

func normalizeFindingFilter(f FindingFilter) (FindingFilter, error) {
	var err error
	f.Selector, err = f.Selector.normalized()
	if err != nil {
		return FindingFilter{}, err
	}
	f.Teams = normalizedSet(f.Teams)
	f.VulnerabilityIDs = normalizedSet(f.VulnerabilityIDs)
	f.Severities = normalizedSet(f.Severities)
	if len(f.Teams) == 0 {
		f.Teams = nil
	}
	if len(f.VulnerabilityIDs) == 0 {
		f.VulnerabilityIDs = nil
	}
	if len(f.Severities) == 0 {
		f.Severities = nil
	}
	if f.PackageType != "" && !packageurl.TypePattern.MatchString(f.PackageType) {
		return FindingFilter{}, fmt.Errorf("package type %q is invalid: %w", f.PackageType, ErrInvalid)
	}
	f.PackageType = strings.ToLower(f.PackageType)
	if f.Package != "" {
		p, err := packageurl.FromString(f.Package)
		if err != nil {
			return FindingFilter{}, fmt.Errorf("package %q is not a purl: %w", f.Package, ErrInvalid)
		}
		f.Package = p.ToString()
		if p.Version == "" {
			key, err := purl.PackageKey(f.Package)
			if err != nil {
				return FindingFilter{}, fmt.Errorf("package %q is not a purl: %w", f.Package, ErrInvalid)
			}
			f.Package = key
		}
	}
	return f, nil
}

func findingBinding(filter FindingFilter, order FindingOrder) (string, error) {
	return queryBinding(filter, order)
}

func queryBinding(filter FindingFilter, order any) (string, error) {
	b, err := json.Marshal(struct {
		Filter FindingFilter
		Order  any
	}{filter, order})
	if err != nil {
		return "", fmt.Errorf("encoding finding query: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type findingCursor struct {
	Version         int          `json:"version"`
	Binding         string       `json:"binding"`
	Environment     string       `json:"e"`
	Team            string       `json:"t"`
	Workload        string       `json:"w"`
	VulnerabilityID string       `json:"v"`
	PURL            string       `json:"p"`
	Severity        v0s.Severity `json:"s,omitempty"`
}

func (c findingCursor) validate(binding string, order FindingOrder) error {
	if c.Version != 1 {
		return fmt.Errorf("incompatible finding cursor version; restart pagination without a token: %w", ErrInvalid)
	}
	if c.Binding != binding {
		return fmt.Errorf("finding cursor filter or order changed; restart pagination without a token: %w", ErrInvalid)
	}
	if c.Environment == "" || c.Team == "" || c.Workload == "" || c.VulnerabilityID == "" || c.PURL == "" {
		return fmt.Errorf("incomplete finding cursor; restart pagination without a token: %w", ErrInvalid)
	}
	if order.Field == FindingOrderSeverity {
		switch c.Severity {
		case v0s.SeverityLow, v0s.SeverityMedium, v0s.SeverityHigh, v0s.SeverityCritical, v0s.SeverityUnknown:
		default:
			return fmt.Errorf("invalid finding cursor severity; restart pagination without a token: %w", ErrInvalid)
		}
	}
	return nil
}

func findingPageToken(f WorkloadFinding, binding string, order FindingOrder) (string, error) {
	cursor := findingCursor{
		Version: 1, Binding: binding,
		Environment: f.Workload.Environment, Team: f.Workload.Team, Workload: f.Workload.Name,
		VulnerabilityID: f.Finding.VulnerabilityID, PURL: f.Finding.PURL,
	}
	if order.Field == FindingOrderSeverity {
		cursor.Severity = f.Finding.Severity
	}
	return encodePageToken(cursor)
}

func (o FindingOrder) severityRank(column string) string {
	values := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if o.Direction == FindingOrderDESC {
		slices.Reverse(values)
	}
	sql := "CASE " + column
	for rank, severity := range values {
		sql += fmt.Sprintf(" WHEN '%s' THEN %d", severity, rank)
	}
	return sql + " ELSE 4 END"
}

func (o FindingOrder) sql() string {
	switch o.Field {
	case FindingOrderSeverity:
		return o.severityRank("f.severity") + ", f.vulnerability_id, w.environment, w.team, w.name, f.purl"
	case FindingOrderVulnerabilityID:
		direction := "ASC"
		if o.Direction == FindingOrderDESC {
			direction = "DESC"
		}
		return "f.vulnerability_id " + direction + ", w.environment, w.team, w.name, f.purl"
	default:
		return "w.environment, w.team, w.name, f.vulnerability_id, f.purl"
	}
}

func (o FindingOrder) after(c findingCursor, args *sqlArgs) []string {
	env, team, workload := args.add(c.Environment), args.add(c.Team), args.add(c.Workload)
	id, pkg := args.add(c.VulnerabilityID), args.add(c.PURL)
	switch o.Field {
	case FindingOrderSeverity:
		return []string{fmt.Sprintf("(%s, f.vulnerability_id, w.environment, w.team, w.name, f.purl) > (%s, %s, %s, %s, %s, %s)",
			o.severityRank("f.severity"), o.severityRank(args.add(string(c.Severity))+"::text"), id, env, team, workload, pkg)}
	case FindingOrderVulnerabilityID:
		op := ">"
		if o.Direction == FindingOrderDESC {
			op = "<"
		}
		return []string{fmt.Sprintf("(f.vulnerability_id %s %s OR (f.vulnerability_id = %s AND (w.environment, w.team, w.name, f.purl) > (%s, %s, %s, %s)))",
			op, id, id, env, team, workload, pkg)}
	default:
		return []string{
			fmt.Sprintf("(w.environment, w.team, w.name) >= (%s, %s, %s)", env, team, workload),
			fmt.Sprintf("((w.environment, w.team, w.name) <> (%s, %s, %s) OR (f.vulnerability_id, f.purl) > (%s, %s))",
				env, team, workload, id, pkg),
		}
	}
}
