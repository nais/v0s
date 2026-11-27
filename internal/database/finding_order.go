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

func normalizeUnscopedFindingFilter(f FindingFilter) (FindingFilter, error) {
	if len(f.Teams) > 0 || f.Environment != "" || f.Workload != "" || f.Selector != nil {
		return FindingFilter{}, fmt.Errorf("finding filter scope must be empty; use workload selection: %w", ErrInvalid)
	}
	return normalizeFindingFilter(f)
}

func findingBinding(filter FindingFilter, order FindingOrder) (string, error) {
	return queryBinding(filter, order)
}

func queryBinding(filter any, order any) (string, error) {
	b, err := json.Marshal(struct {
		Filter any
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
	if c.Version != order.cursorVersion() {
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

func (o FindingOrder) cursorVersion() int {
	if o.Field == FindingOrderSeverity && o.Direction == FindingOrderASC {
		return 2
	}
	return 1
}

func newFindingCursor(f WorkloadFinding, binding string, order FindingOrder) findingCursor {
	cursor := findingCursor{
		Version: order.cursorVersion(), Binding: binding,
		Environment: f.Workload.Environment, Team: f.Workload.Team, Workload: f.Workload.Name,
		VulnerabilityID: f.Finding.VulnerabilityID, PURL: f.Finding.PURL,
	}
	if order.Field == FindingOrderSeverity {
		cursor.Severity = f.Finding.Severity
	}
	return cursor
}

func findingPageToken(f WorkloadFinding, binding string, order FindingOrder) (string, error) {
	return encodePageToken(newFindingCursor(f, binding, order))
}

func severityRank(column string) string {
	values := []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	sql := "CASE " + column
	for _, severity := range values {
		sql += fmt.Sprintf(" WHEN '%s' THEN %d", severity, severityValue(v0s.Severity(severity)))
	}
	return sql + " ELSE 0 END"
}

func (o FindingOrder) keyset() keysetOrder {
	env := keysetTerm{column: "w.environment"}
	team := keysetTerm{column: "w.team"}
	workload := keysetTerm{column: "w.name"}
	id := keysetTerm{column: "f.vulnerability_id"}
	pkg := keysetTerm{column: "f.purl"}
	switch o.Field {
	case FindingOrderSeverity:
		return keysetOrder{{severityRank("f.severity"), o.Direction == FindingOrderDESC}, id, env, team, workload, pkg}
	case FindingOrderVulnerabilityID:
		id.desc = o.Direction == FindingOrderDESC
		return keysetOrder{id, env, team, workload, pkg}
	default:
		return keysetOrder{env, team, workload, id, pkg}
	}
}

func (c findingCursor) values(o FindingOrder) []any {
	switch o.Field {
	case FindingOrderSeverity:
		return []any{severityValue(c.Severity), c.VulnerabilityID, c.Environment, c.Team, c.Workload, c.PURL}
	case FindingOrderVulnerabilityID:
		return []any{c.VulnerabilityID, c.Environment, c.Team, c.Workload, c.PURL}
	default:
		return []any{c.Environment, c.Team, c.Workload, c.VulnerabilityID, c.PURL}
	}
}

func severityValue(severity v0s.Severity) int {
	switch severity {
	case v0s.SeverityLow:
		return 1
	case v0s.SeverityMedium:
		return 2
	case v0s.SeverityHigh:
		return 3
	case v0s.SeverityCritical:
		return 4
	default:
		return 0
	}
}
