package database_test

import (
	"context"
	"slices"
	"testing"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestSyncWorkloadImages(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	steps := []struct {
		cluster string
		ws      []v0s.WorkloadImage
		want    []string
	}{
		{
			cluster: "c1",
			ws:      []v0s.WorkloadImage{workloadImage("c1", "a", "img-a"), workloadImage("c1", "b", "img-b"), workloadImage("c1", "b", "img-b")},
			want:    []string{"c1 a img-a", "c1 b img-b"},
		},
		{
			cluster: "c2",
			ws:      []v0s.WorkloadImage{workloadImage("c2", "a", "img-a")},
			want:    []string{"c1 a img-a", "c1 b img-b", "c2 a img-a"},
		},
		{
			cluster: "c1",
			ws:      []v0s.WorkloadImage{workloadImage("c1", "b", "img-c")},
			want:    []string{"c1 b img-c", "c2 a img-a"},
		},
		{
			cluster: "c2",
			want:    []string{"c1 b img-c"},
		},
	}
	for i, s := range steps {
		if err := db.SyncWorkloadImages(ctx, s.cluster, s.ws); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		got := queryStrings(t, db, `
			SELECT w.cluster || ' ' || w.workload || ' ' || i.name
			FROM workload_images w JOIN images i ON i.id = w.image_id
			ORDER BY 1`)
		if !slices.Equal(got, s.want) {
			t.Errorf("step %d: workload images = %q, want %q", i, got, s.want)
		}
	}

	got := queryStrings(t, db, `SELECT name || ' ' || sbom_state FROM images ORDER BY name`)
	want := []string{"img-a pending", "img-b pending", "img-c pending"}
	if !slices.Equal(got, want) {
		t.Errorf("images = %q, want %q", got, want)
	}

	if err := db.SyncWorkloadImages(ctx, "c1", []v0s.WorkloadImage{workloadImage("c2", "a", "img-a")}); err == nil {
		t.Error("sync with a workload image from another cluster succeeded, want error")
	}
}
