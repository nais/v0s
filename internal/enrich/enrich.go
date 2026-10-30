// Package enrich downloads and parses the public FIRST EPSS and CISA KEV feeds.
package enrich

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nais/v0s"
)

const (
	// DefaultEPSSURL is the daily FIRST EPSS scores for all CVEs, as gzipped CSV.
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	// DefaultKEVURL is the CISA Known Exploited Vulnerabilities catalog, as JSON.
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// cveID matches a CVE identifier. Both feeds key their entries by CVE.
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// FetchEPSS downloads and parses the daily FIRST EPSS CSV (gzip). It returns an error for a feed
// without scores or with an invalid row, so a broken upstream never wipes stored scores.
func FetchEPSS(ctx context.Context, c *http.Client, url string) ([]v0s.EPSS, error) {
	body, err := get(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	gz, err := gzip.NewReader(body)
	if err != nil {
		return nil, fmt.Errorf("reading EPSS gzip: %w", err)
	}
	defer gz.Close()
	r := bufio.NewReader(gz)

	// The first line is a comment: #model_version:v2026.06.15,score_date:2026-10-29T12:03:14Z
	comment, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading EPSS header: %w", err)
	}
	date, err := epssScoreDate(comment)
	if err != nil {
		return nil, err
	}

	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 3
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading EPSS columns: %w", err)
	}
	if header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return nil, fmt.Errorf("unexpected EPSS columns %q", header)
	}

	var scores []v0s.EPSS
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading EPSS row: %w", err)
		}
		if !cveID.MatchString(rec[0]) {
			return nil, fmt.Errorf("EPSS row has invalid CVE ID %q", rec[0])
		}
		score, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			return nil, fmt.Errorf("parsing EPSS score for %s: %w", rec[0], err)
		}
		percentile, err := strconv.ParseFloat(rec[2], 64)
		if err != nil {
			return nil, fmt.Errorf("parsing EPSS percentile for %s: %w", rec[0], err)
		}
		// Written so that NaN fails too.
		if !(score >= 0 && score <= 1 && percentile >= 0 && percentile <= 1) {
			return nil, fmt.Errorf("EPSS score %v or percentile %v for %s is outside [0,1]", score, percentile, rec[0])
		}
		scores = append(scores, v0s.EPSS{CVE: rec[0], Score: score, Percentile: percentile, Date: date})
	}
	if len(scores) == 0 {
		return nil, errors.New("EPSS feed has no scores")
	}
	return scores, nil
}

// epssScoreDate returns the day of score_date in the EPSS header comment.
func epssScoreDate(comment string) (time.Time, error) {
	comment, ok := strings.CutPrefix(strings.TrimSpace(comment), "#")
	if !ok {
		return time.Time{}, errors.New("EPSS feed does not start with a comment line")
	}
	for field := range strings.SplitSeq(comment, ",") {
		key, value, _ := strings.Cut(field, ":")
		if key != "score_date" {
			continue
		}
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing EPSS score_date: %w", err)
		}
		t = t.UTC()
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
	}
	return time.Time{}, errors.New("EPSS header has no score_date")
}

// FetchKEV downloads and parses the CISA KEV JSON feed. It returns an error for a feed without
// entries, with an invalid entry, or with fewer or more entries than its count, so a broken
// upstream never wipes stored entries.
func FetchKEV(ctx context.Context, c *http.Client, url string) ([]v0s.KEV, error) {
	body, err := get(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var catalog struct {
		Count           int `json:"count"`
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("decoding KEV catalog: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil, errors.New("KEV catalog has no vulnerabilities")
	}
	if len(catalog.Vulnerabilities) != catalog.Count {
		return nil, fmt.Errorf("KEV catalog has %d vulnerabilities, but count %d", len(catalog.Vulnerabilities), catalog.Count)
	}

	kevs := make([]v0s.KEV, 0, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		if !cveID.MatchString(v.CVEID) {
			return nil, fmt.Errorf("KEV entry has invalid CVE ID %q", v.CVEID)
		}
		added, err := time.Parse(time.DateOnly, v.DateAdded)
		if err != nil {
			return nil, fmt.Errorf("parsing KEV dateAdded for %s: %w", v.CVEID, err)
		}
		var due time.Time
		if v.DueDate != "" {
			if due, err = time.Parse(time.DateOnly, v.DueDate); err != nil {
				return nil, fmt.Errorf("parsing KEV dueDate for %s: %w", v.CVEID, err)
			}
		}
		kevs = append(kevs, v0s.KEV{
			CVE:                     v.CVEID,
			DateAdded:               added,
			DueDate:                 due,
			KnownRansomwareCampaign: v.KnownRansomwareCampaignUse == "Known",
		})
	}
	return kevs, nil
}

func get(ctx context.Context, c *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}
