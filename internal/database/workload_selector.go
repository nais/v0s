package database

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

type WorkloadSelector struct {
	Workloads []WorkloadRef
}

func (s *WorkloadSelector) normalized() (*WorkloadSelector, error) {
	if s == nil {
		return nil, nil
	}
	workloads := append([]WorkloadRef{}, s.Workloads...)
	for i, w := range workloads {
		if strings.TrimSpace(w.Environment) == "" || strings.TrimSpace(w.Team) == "" || strings.TrimSpace(w.Name) == "" {
			return nil, fmt.Errorf("workload selector entry %d requires environment, team and name: %w", i, ErrInvalid)
		}
	}
	slices.SortFunc(workloads, func(a, b WorkloadRef) int {
		return cmp.Or(cmp.Compare(a.Environment, b.Environment), cmp.Compare(a.Team, b.Team), cmp.Compare(a.Name, b.Name))
	})
	return &WorkloadSelector{Workloads: slices.Compact(workloads)}, nil
}

func (s *WorkloadSelector) condition(args *sqlArgs) string {
	if s == nil {
		return ""
	}
	if len(s.Workloads) == 0 {
		return "false"
	}
	environments, teams, names := make([]string, len(s.Workloads)), make([]string, len(s.Workloads)), make([]string, len(s.Workloads))
	for i, w := range s.Workloads {
		environments[i], teams[i], names[i] = w.Environment, w.Team, w.Name
	}
	return fmt.Sprintf(`EXISTS (
		SELECT 1 FROM unnest(%s::text[], %s::text[], %s::text[]) AS selection(environment, team, name)
		WHERE (w.environment, w.team, w.name) = (selection.environment, selection.team, selection.name)
	)`, args.add(environments), args.add(teams), args.add(names))
}
