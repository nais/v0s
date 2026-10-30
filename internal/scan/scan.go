// Package scan matches SBOMs against the Trivy vulnerability DB and keeps that DB up to date.
//
// It is the only package that imports Trivy. trivy-db keeps the open DB in a
// process-global handle, so there must be at most one Scanner per process.
package scan

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ospkgdetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/purl"
)

// ErrNoDB is returned by Scan when no vulnerability DB is loaded.
var ErrNoDB = errors.New("no vulnerability DB loaded")

// Scanner matches SBOMs against a local Trivy vulnerability DB and keeps that DB up to date.
type Scanner struct {
	dir   string
	repos []string
	log   *slog.Logger

	// updateMu serializes Update and guards digest.
	updateMu sync.Mutex
	// digest is the manifest digest of the newest DB artifact seen, loaded or not.
	digest string

	// mu is held for reading by scans and for writing while the DB is swapped.
	mu      sync.RWMutex
	current string    // directory of the loaded DB, empty if none
	version time.Time // UpdatedAt of the loaded DB
}

// DBVersion is the UpdatedAt of the loaded DB, or zero if none is loaded.
func (s *Scanner) DBVersion() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Scan matches a CycloneDX JSON SBOM and returns the result and the DB version it used.
// It returns ErrNoDB if no DB is loaded.
func (s *Scanner) Scan(ctx context.Context, doc []byte) (v0s.ScanResult, time.Time, error) {
	target, err := decode(ctx, doc)
	if err != nil {
		return v0s.ScanResult{}, time.Time{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == "" {
		return v0s.ScanResult{}, time.Time{}, ErrNoDB
	}
	vulns, err := detect(ctx, target)
	if err != nil {
		return v0s.ScanResult{}, time.Time{}, err
	}
	res, err := result(target, vulns)
	if err != nil {
		return v0s.ScanResult{}, time.Time{}, err
	}
	return res, s.version, nil
}

// decode turns a CycloneDX JSON SBOM into a Trivy scan target.
// Components without a purl or with a purl type Trivy does not support are dropped.
func decode(ctx context.Context, doc []byte) (types.ScanTarget, error) {
	if ok, err := sbom.IsCycloneDXJSON(bytes.NewReader(doc)); err != nil {
		return types.ScanTarget{}, fmt.Errorf("detecting SBOM format: %w", err)
	} else if !ok {
		return types.ScanTarget{}, errors.New("SBOM is not CycloneDX JSON")
	}
	bom, err := sbom.Decode(ctx, bytes.NewReader(doc), sbom.FormatCycloneDXJSON)
	if err != nil {
		return types.ScanTarget{}, fmt.Errorf("decoding SBOM: %w", err)
	}

	target := types.ScanTarget{Name: "sbom", Applications: bom.Applications}
	if bom.Metadata.OS != nil {
		target.OS = *bom.Metadata.OS
	}
	for _, info := range bom.Packages {
		target.Packages = append(target.Packages, info.Packages...)
	}
	return target, nil
}

// detect finds vulnerabilities in the OS and language packages of target and fills in
// their details. It is the vulnerability part of Trivy's local scan service
// (pkg/scan/local Service.ScanTarget) without its analyzers and other scanners.
// It reads the global trivy-db handle, so the caller must hold Scanner.mu for reading.
func detect(ctx context.Context, target types.ScanTarget) ([]types.DetectedVulnerability, error) {
	opts := types.ScanOptions{Scanners: types.Scanners{types.VulnerabilityScanner}}

	osResult, _, err := ospkg.NewScanner().Scan(ctx, target, opts)
	if err != nil && !errors.Is(err, ospkgdetector.ErrUnsupportedOS) {
		return nil, fmt.Errorf("scanning OS packages: %w", err)
	}
	vulns := osResult.Vulnerabilities

	langResults, err := langpkg.NewScanner().Scan(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("scanning language packages: %w", err)
	}
	for _, r := range langResults {
		vulns = append(vulns, r.Vulnerabilities...)
	}

	vulnerability.NewClient(trivydb.Config{}).FillInfo(vulns, []dbtypes.SourceID{"auto"})
	return vulns, nil
}

// result maps Trivy's packages and vulnerabilities to v0s types, sorted and deduplicated.
func result(target types.ScanTarget, vulns []types.DetectedVulnerability) (v0s.ScanResult, error) {
	var res v0s.ScanResult

	pkgs := slices.Clone(target.Packages)
	for _, app := range target.Applications {
		pkgs = append(pkgs, app.Packages...)
	}
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		if pkg.Identifier.PURL == nil {
			continue
		}
		p := pkg.Identifier.PURL.String()
		if seen[p] {
			continue
		}
		seen[p] = true
		key, err := purl.PackageKey(p)
		if err != nil {
			return v0s.ScanResult{}, fmt.Errorf("component %s: %w", p, err)
		}
		res.Components = append(res.Components, v0s.Component{
			PURL:       p,
			PackageKey: key,
			Name:       pkg.Name,
			Version:    pkg.Identifier.PURL.Version,
		})
	}

	type findingKey struct{ id, purl string }
	findings := make(map[findingKey]bool)
	records := make(map[string]*v0s.Vulnerability)
	for _, v := range vulns {
		if v.PkgIdentifier.PURL == nil {
			continue
		}
		p := v.PkgIdentifier.PURL.String()
		if records[v.VulnerabilityID] == nil {
			records[v.VulnerabilityID] = record(v)
		}
		rec := records[v.VulnerabilityID]
		for _, alias := range v.VendorIDs {
			if alias != v.VulnerabilityID && !slices.Contains(rec.Aliases, alias) {
				rec.Aliases = append(rec.Aliases, alias)
			}
		}

		if findings[findingKey{v.VulnerabilityID, p}] {
			continue
		}
		findings[findingKey{v.VulnerabilityID, p}] = true
		key, err := purl.PackageKey(p)
		if err != nil {
			return v0s.ScanResult{}, fmt.Errorf("finding %s in %s: %w", v.VulnerabilityID, p, err)
		}
		var dataSource string
		if v.DataSource != nil {
			dataSource = string(v.DataSource.ID)
		}
		// FillInfo puts the severity it selected in the deprecated field, also when it has no source.
		//lint:ignore SA1019 this is the severity Trivy reports for the finding.
		sev := severity(v.Severity)
		res.Findings = append(res.Findings, v0s.Finding{
			VulnerabilityID:  v.VulnerabilityID,
			PURL:             p,
			PackageKey:       key,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Status:           v.Status.String(),
			Severity:         sev,
			SeveritySource:   string(v.SeveritySource),
			DataSource:       dataSource,
		})
	}
	for _, rec := range records {
		slices.Sort(rec.Aliases)
		res.Vulnerabilities = append(res.Vulnerabilities, *rec)
	}

	slices.SortFunc(res.Components, func(a, b v0s.Component) int { return strings.Compare(a.PURL, b.PURL) })
	slices.SortFunc(res.Findings, func(a, b v0s.Finding) int {
		return cmp.Or(strings.Compare(a.VulnerabilityID, b.VulnerabilityID), strings.Compare(a.PURL, b.PURL))
	})
	slices.SortFunc(res.Vulnerabilities, func(a, b v0s.Vulnerability) int { return strings.Compare(a.ID, b.ID) })
	return res, nil
}

// record returns the vulnerability record of v, without aliases.
func record(v types.DetectedVulnerability) *v0s.Vulnerability {
	rec := &v0s.Vulnerability{
		ID:          v.VulnerabilityID,
		Title:       v.Title,
		Description: v.Description,
		Severities:  make(map[string]v0s.Severity, len(v.VendorSeverity)),
		CVSS:        make(map[string]v0s.CVSS, len(v.CVSS)),
		References:  slices.Clone(v.References),
	}
	for source, s := range v.VendorSeverity {
		rec.Severities[string(source)] = severity(s.String())
	}
	for source, c := range v.CVSS {
		rec.CVSS[string(source)] = v0s.CVSS{
			V3Vector:  c.V3Vector,
			V3Score:   c.V3Score,
			V40Vector: c.V40Vector,
			V40Score:  c.V40Score,
		}
	}
	if v.PublishedDate != nil {
		rec.PublishedAt = *v.PublishedDate
	}
	if v.LastModifiedDate != nil {
		rec.ModifiedAt = *v.LastModifiedDate
	}
	return rec
}

// severity maps a Trivy severity name to a v0s severity, UNKNOWN if it is not one.
func severity(s string) v0s.Severity {
	switch sev := v0s.Severity(strings.ToUpper(s)); sev {
	case v0s.SeverityLow, v0s.SeverityMedium, v0s.SeverityHigh, v0s.SeverityCritical:
		return sev
	}
	return v0s.SeverityUnknown
}
