package database

import (
	"context"
	"fmt"

	"github.com/nais/v0s"
)

// Workload is a workload and the image it is deployed with.
type Workload struct {
	Environment string
	Team        string
	Name        string
	Image       v0s.Image
}

// WorkloadFilter narrows workloads. Empty fields do not filter.
type WorkloadFilter struct {
	Teams       []string
	Environment string
}

type workloadCursor struct {
	Environment string `json:"e"`
	Team        string `json:"t"`
	Name        string `json:"w"`
}

// ListWorkloads lists workloads ordered by environment, team and name.
func (db *DB) ListWorkloads(ctx context.Context, filter WorkloadFilter, page Page) ([]Workload, string, error) {
	var cursor workloadCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var (
		args  sqlArgs
		where []string
	)
	if len(filter.Teams) > 0 {
		where = append(where, "team = ANY("+args.add(filter.Teams)+")")
	}
	if filter.Environment != "" {
		where = append(where, "environment = "+args.add(filter.Environment))
	}
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(environment, team, workload) > (%s, %s, %s)",
			args.add(cursor.Environment), args.add(cursor.Team), args.add(cursor.Name)))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT wi.environment, wi.team, wi.workload, `+imageColumns+`
		FROM workload_images wi
		JOIN images i ON i.id = wi.image_id
		WHERE `+and(where)+`
		ORDER BY wi.environment, wi.team, wi.workload
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}
	defer rows.Close()

	var workloads []Workload
	for rows.Next() {
		var (
			w   Workload
			img imageScan
		)
		if err := rows.Scan(append([]any{&w.Environment, &w.Team, &w.Name}, img.dest()...)...); err != nil {
			return nil, "", fmt.Errorf("scanning workload: %w", err)
		}
		w.Image = img.image()
		workloads = append(workloads, w)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}

	var next string
	if len(workloads) > limit {
		workloads = workloads[:limit]
		last := workloads[limit-1]
		next, err = encodePageToken(workloadCursor{Environment: last.Environment, Team: last.Team, Name: last.Name})
		if err != nil {
			return nil, "", err
		}
	}
	return workloads, next, nil
}
