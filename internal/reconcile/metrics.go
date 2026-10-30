package reconcile

import (
	"context"
	"time"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// countTimeout bounds the query behind v0s_images, so a slow database cannot stall a scrape.
const countTimeout = 5 * time.Second

// Metrics are the loop metrics the Reconciler updates.
type Metrics struct {
	scanDuration      prometheus.Histogram
	scans             *prometheus.CounterVec
	fetches           *prometheus.CounterVec
	dbUpdates         *prometheus.CounterVec
	enrichmentSuccess *prometheus.GaugeVec
}

// NewMetrics registers the loop metrics with reg. It also registers v0s_images, which counts db's
// in-use images at scrape time, and v0s_trivy_db_version_timestamp_seconds, both against the DB
// version scanner has loaded.
func NewMetrics(reg prometheus.Registerer, db *database.DB, scanner Scanner) *Metrics {
	f := promauto.With(reg)
	f.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "v0s_trivy_db_version_timestamp_seconds",
		Help: "UpdatedAt of the loaded vulnerability DB, 0 if none is loaded.",
	}, func() float64 {
		v := scanner.DBVersion()
		if v.IsZero() {
			return 0
		}
		return float64(v.Unix())
	})
	reg.MustRegister(&imagesCollector{db: db, scanner: scanner})
	return &Metrics{
		scanDuration: f.NewHistogram(prometheus.HistogramOpts{
			Name:    "v0s_scan_duration_seconds",
			Help:    "Time spent matching one SBOM against the vulnerability DB.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}),
		scans: f.NewCounterVec(prometheus.CounterOpts{
			Name: "v0s_scans_total",
			Help: "SBOM scans by result: ok or error.",
		}, []string{"result"}),
		fetches: f.NewCounterVec(prometheus.CounterOpts{
			Name: "v0s_fetches_total",
			Help: "SBOM fetches by result: found, not_found or error.",
		}, []string{"result"}),
		dbUpdates: f.NewCounterVec(prometheus.CounterOpts{
			Name: "v0s_trivy_db_updates_total",
			Help: "Vulnerability DB update checks by result: updated, unchanged or error.",
		}, []string{"result"}),
		enrichmentSuccess: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "v0s_enrichment_last_success_timestamp_seconds",
			Help: "When this replica last replaced a feed's table, by feed: epss or kev.",
		}, []string{"feed"}),
	}
}

// imageStates are the label pairs of v0s_images. All are reported, with zero if no image is in
// that state, so that series do not disappear.
var imageStates = []imageState{
	{v0s.SBOMPending, ""},
	{v0s.SBOMMissing, ""},
	{v0s.SBOMFailed, ""},
	{v0s.SBOMFetched, "pending"},
	{v0s.SBOMFetched, "current"},
	{v0s.SBOMFetched, "failed"},
}

type imageState struct {
	sbom v0s.SBOMState
	scan string
}

var imagesDesc = prometheus.NewDesc(
	"v0s_images",
	"In-use images by SBOM state and, for fetched SBOMs, scan state against the loaded DB: "+
		"current (scanned with it or newer), failed (scanning with it or newer failed) or pending.",
	[]string{"sbom", "scan"}, nil,
)

// imagesCollector reports v0s_images, counted in the database at scrape time.
type imagesCollector struct {
	db      *database.DB
	scanner Scanner
}

func (c *imagesCollector) Describe(ch chan<- *prometheus.Desc) { ch <- imagesDesc }

func (c *imagesCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), countTimeout)
	defer cancel()
	counts, err := c.db.CountImageStates(ctx, c.scanner.DBVersion())
	if err != nil {
		ch <- prometheus.NewInvalidMetric(imagesDesc, err)
		return
	}
	n := map[imageState]int{}
	for _, c := range counts {
		n[imageState{c.SBOM, c.Scan}] = c.Count
	}
	for _, s := range imageStates {
		ch <- prometheus.MustNewConstMetric(imagesDesc, prometheus.GaugeValue, float64(n[s]), string(s.sbom), s.scan)
	}
}
