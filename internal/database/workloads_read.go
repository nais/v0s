package database

import (
	"context"
	"fmt"

	"github.com/nais/v0s"
)

// Workload is a running workload and the images its containers run.
type Workload struct {
	Cluster    string
	Namespace  string
	Name       string
	OwnerKind  string
	Containers []WorkloadContainer // ordered by name, then image
}

// WorkloadContainer is a container in a workload and the image it runs.
type WorkloadContainer struct {
	Name  string
	Image v0s.Image
}

// WorkloadFilter narrows workloads. Empty fields do not filter.
type WorkloadFilter struct {
	Namespaces []string
	Cluster    string
}

type workloadCursor struct {
	Cluster   string `json:"c"`
	Namespace string `json:"n"`
	Name      string `json:"w"`
}

// ListWorkloads lists running workloads ordered by cluster, namespace and name.
func (db *DB) ListWorkloads(ctx context.Context, filter WorkloadFilter, page Page) ([]Workload, string, error) {
	var cursor workloadCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var (
		args  sqlArgs
		where []string
	)
	if len(filter.Namespaces) > 0 {
		where = append(where, "namespace = ANY("+args.add(filter.Namespaces)+")")
	}
	if filter.Cluster != "" {
		where = append(where, "cluster = "+args.add(filter.Cluster))
	}
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(cluster, namespace, workload) > (%s, %s, %s)",
			args.add(cursor.Cluster), args.add(cursor.Namespace), args.add(cursor.Name)))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		WITH page AS (
			SELECT cluster, namespace, workload, max(owner_kind) AS owner_kind
			FROM workload_images
			WHERE `+and(where)+`
			GROUP BY cluster, namespace, workload
			ORDER BY cluster, namespace, workload
			LIMIT `+args.add(limit+1)+`
		)
		SELECT p.cluster, p.namespace, p.workload, p.owner_kind, wi.container, `+imageColumns+`
		FROM page p
		JOIN workload_images wi USING (cluster, namespace, workload)
		JOIN images i ON i.id = wi.image_id
		ORDER BY p.cluster, p.namespace, p.workload, wi.container, i.name, i.digest`, args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}
	defer rows.Close()

	var workloads []Workload
	for rows.Next() {
		var (
			w   Workload
			c   WorkloadContainer
			img imageScan
		)
		if err := rows.Scan(append([]any{&w.Cluster, &w.Namespace, &w.Name, &w.OwnerKind, &c.Name}, img.dest()...)...); err != nil {
			return nil, "", fmt.Errorf("scanning workload: %w", err)
		}
		c.Image = img.image()
		if n := len(workloads); n == 0 || workloads[n-1].Cluster != w.Cluster || workloads[n-1].Namespace != w.Namespace || workloads[n-1].Name != w.Name {
			workloads = append(workloads, w)
		}
		last := &workloads[len(workloads)-1]
		last.Containers = append(last.Containers, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}

	var next string
	if len(workloads) > limit {
		workloads = workloads[:limit]
		last := workloads[limit-1]
		next, err = encodePageToken(workloadCursor{Cluster: last.Cluster, Namespace: last.Namespace, Name: last.Name})
		if err != nil {
			return nil, "", err
		}
	}
	return workloads, next, nil
}
