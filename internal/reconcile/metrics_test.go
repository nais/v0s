package reconcile

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestInventorySyncMetrics(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	reg := prometheus.NewRegistry()
	r := &Reconciler{
		DB: db, Inventory: fakeInventory{}, Log: discard,
		Metrics: NewMetrics(reg, db, fakeScanner{}),
	}
	value := func(metric prometheus.Metric) float64 {
		t.Helper()
		var m dto.Metric
		if err := metric.Write(&m); err != nil {
			t.Fatal(err)
		}
		if m.Gauge != nil {
			return m.GetGauge().GetValue()
		}
		return m.GetCounter().GetValue()
	}
	check := func(ok, failed, success float64) {
		t.Helper()
		if got := value(r.Metrics.inventorySyncs.WithLabelValues("ok")); got != ok {
			t.Errorf("successful syncs = %v, want %v", got, ok)
		}
		if got := value(r.Metrics.inventorySyncs.WithLabelValues("error")); got != failed {
			t.Errorf("failed syncs = %v, want %v", got, failed)
		}
		if got := value(r.Metrics.inventorySuccess); got != success {
			t.Errorf("last success = %v, want %v", got, success)
		}
	}

	// A replica that cannot take the lock has done no work.
	if err := db.WithLock(ctx, "sync", r.sync); err != nil {
		t.Fatal(err)
	}
	check(0, 0, 0)

	before := float64(time.Now().Unix())
	if err := r.sync(ctx); err != nil {
		t.Fatal(err)
	}
	success := value(r.Metrics.inventorySuccess)
	if success < before || success > float64(time.Now().Unix()+1) {
		t.Fatalf("last success = %v, want current time", success)
	}
	check(1, 0, success)

	r.Inventory = fakeInventory(nil)
	if err := r.sync(ctx); err == nil {
		t.Fatal("expected inventory failure")
	}
	check(1, 1, success)

	shutdown, cancel := context.WithCancel(ctx)
	r.Inventory = cancelInventory{cancel: cancel}
	if err := r.sync(shutdown); err == nil {
		t.Fatal("expected shutdown cancellation")
	}
	check(1, 1, success)
}

type cancelInventory struct{ cancel context.CancelFunc }

func (inv cancelInventory) Snapshot(ctx context.Context) (map[string][]v0s.WorkloadImage, error) {
	inv.cancel()
	return nil, ctx.Err()
}

func TestImagesMetric(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v3 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	names := []string{"pending", "missing", "unreachable", "unscanned", "old", "current", "newer", "failed", "unused"}
	var ws []v0s.WorkloadImage
	for _, n := range names {
		ws = append(ws, v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: n, ImageName: "registry/" + n, Digest: "sha256:" + n})
	}
	if err := db.SyncWorkloadImages(ctx, "dev", ws); err != nil {
		t.Fatal(err)
	}
	images, err := db.DueSBOMFetches(ctx, len(names))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	for _, img := range images {
		ids[strings.TrimPrefix(img.Name, "registry/")] = img.ID
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(db.RecordSBOMFailure(ctx, ids["missing"], v0s.SBOMMissing, "no attestation", time.Now()))
	must(db.RecordSBOMFailure(ctx, ids["unreachable"], v0s.SBOMFailed, "registry down", time.Now()))
	for _, n := range []string{"unscanned", "old", "current", "newer", "failed", "unused"} {
		must(db.StoreSBOM(ctx, ids[n], []byte("sbom")))
	}
	must(db.StoreScan(ctx, ids["old"], v1, v0s.ScanResult{}))
	must(db.StoreScan(ctx, ids["current"], v2, v0s.ScanResult{}))
	must(db.StoreScan(ctx, ids["newer"], v3, v0s.ScanResult{}))
	must(db.StoreScan(ctx, ids["unused"], v2, v0s.ScanResult{}))
	must(db.RecordScanFailure(ctx, ids["failed"], v2, "boom"))
	must(db.SyncWorkloadImages(ctx, "dev", ws[:len(ws)-1])) // "unused" is no longer in use

	tests := []struct {
		name      string
		dbVersion time.Time
		want      map[string]float64
	}{
		{
			name:      "DB loaded",
			dbVersion: v2,
			want: map[string]float64{
				"pending/": 1, "missing/": 1, "failed/": 1,
				"fetched/pending": 2, "fetched/current": 2, "fetched/failed": 1,
			},
		},
		{
			name: "no DB loaded",
			want: map[string]float64{
				"pending/": 1, "missing/": 1, "failed/": 1,
				"fetched/pending": 5, "fetched/current": 0, "fetched/failed": 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			NewMetrics(reg, db, fakeScanner{version: tt.dbVersion})
			families, err := reg.Gather()
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]float64{}
			for _, f := range families {
				if f.GetName() != "v0s_images" {
					continue
				}
				for _, m := range f.GetMetric() {
					labels := map[string]string{}
					for _, l := range m.GetLabel() {
						labels[l.GetName()] = l.GetValue()
					}
					got[labels["sbom"]+"/"+labels["scan"]] = m.GetGauge().GetValue()
				}
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("v0s_images = %v, want %v", got, tt.want)
			}
		})
	}
}
