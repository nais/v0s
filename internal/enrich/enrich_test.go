package enrich_test

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/enrich"
)

func TestFetchEPSS(t *testing.T) {
	date := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		file    string
		status  int
		want    []v0s.EPSS
		wantErr bool
	}{
		{name: "scores", file: "testdata/epss.csv", status: http.StatusOK, want: []v0s.EPSS{
			{CVE: "CVE-1999-0001", Score: 0.04753, Percentile: 0.9186, Date: date},
			{CVE: "CVE-2021-44228", Score: 0.94358, Percentile: 0.99962, Date: date},
		}},
		{name: "no scores", file: "testdata/epss-empty.csv", status: http.StatusOK, wantErr: true},
		{name: "no score date", file: "testdata/epss-no-date.csv", status: http.StatusOK, wantErr: true},
		{name: "empty CVE ID", file: "testdata/epss-empty-cve.csv", status: http.StatusOK, wantErr: true},
		{name: "NaN score", file: "testdata/epss-nan-score.csv", status: http.StatusOK, wantErr: true},
		{name: "percentile above one", file: "testdata/epss-percentile-above-one.csv", status: http.StatusOK, wantErr: true},
		{name: "server error", file: "testdata/epss.csv", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := readFile(t, tt.file)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				gz := gzip.NewWriter(w)
				_, _ = gz.Write(data)
				_ = gz.Close()
			}))
			defer srv.Close()

			got, err := enrich.FetchEPSS(t.Context(), srv.Client(), srv.URL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("FetchEPSS() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchEPSS(): %v", err)
			}
			if !slices.EqualFunc(got, tt.want, func(a, b v0s.EPSS) bool {
				return a.CVE == b.CVE && a.Score == b.Score && a.Percentile == b.Percentile && a.Date.Equal(b.Date)
			}) {
				t.Errorf("FetchEPSS() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func TestFetchKEV(t *testing.T) {
	day := func(s string) time.Time {
		d, err := time.Parse(time.DateOnly, s)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	tests := []struct {
		name    string
		file    string
		status  int
		want    []v0s.KEV
		wantErr bool
	}{
		{name: "catalog", file: "testdata/kev.json", status: http.StatusOK, want: []v0s.KEV{
			{CVE: "CVE-2021-44228", DateAdded: day("2021-12-10"), DueDate: day("2021-12-24"), KnownRansomwareCampaign: true},
			{CVE: "CVE-2026-97229", DateAdded: day("2026-10-29")},
		}},
		{name: "no vulnerabilities", file: "testdata/kev-empty.json", status: http.StatusOK, wantErr: true},
		{name: "empty CVE ID", file: "testdata/kev-empty-cve.json", status: http.StatusOK, wantErr: true},
		{name: "count mismatch", file: "testdata/kev-count-mismatch.json", status: http.StatusOK, wantErr: true},
		{name: "server error", file: "testdata/kev.json", status: http.StatusServiceUnavailable, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := readFile(t, tt.file)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write(data)
			}))
			defer srv.Close()

			got, err := enrich.FetchKEV(t.Context(), srv.Client(), srv.URL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("FetchKEV() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("FetchKEV(): %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("FetchKEV() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
