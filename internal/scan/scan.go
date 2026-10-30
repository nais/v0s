// Package scan matches SBOMs against the Trivy vulnerability DB and keeps that DB up to date.
//
// It is the only package that imports Trivy. trivy-db keeps the open DB in a
// process-global handle, so there must be at most one Scanner per process.
package scan

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ospkgdetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/package-url/packageurl-go"

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
	// digest is the manifest digest of the DB artifact last swapped in or rejected as
	// not newer. A failed installation leaves it unchanged, so the artifact is retried.
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

// Scan matches a CycloneDX JSON SBOM and returns the result and the version of the DB
// loaded when the scan started. The version is returned also when err != nil, and is
// zero if no DB is loaded, in which case the error is ErrNoDB.
func (s *Scanner) Scan(ctx context.Context, doc []byte) (v0s.ScanResult, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	version := s.version
	if s.current == "" {
		return v0s.ScanResult{}, version, ErrNoDB
	}

	components, target, err := decode(ctx, doc)
	if err != nil {
		return v0s.ScanResult{}, version, err
	}
	vulns, err := detect(ctx, target)
	if err != nil {
		return v0s.ScanResult{}, version, err
	}
	res, err := result(components, vulns)
	if err != nil {
		return v0s.ScanResult{}, version, err
	}
	return res, version, nil
}

// decode parses a CycloneDX JSON SBOM into its inventory and a Trivy scan target.
//
// Trivy reads neither nested components nor component versions missing from the purl,
// and drops purl types it cannot match. So decode flattens nested components, fills
// missing purl versions from the component version, and takes the inventory from every
// component with a valid purl before Trivy sees the document. The metadata component is
// part of the inventory unless it is an OCI image, which is the image itself.
func decode(ctx context.Context, doc []byte) ([]v0s.Component, types.ScanTarget, error) {
	var bom cdx.BOM
	if err := json.Unmarshal(doc, &bom); err != nil {
		return nil, types.ScanTarget{}, fmt.Errorf("decoding SBOM: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, types.ScanTarget{}, errors.New("SBOM is not CycloneDX JSON")
	}
	if bom.SpecVersion == 0 {
		return nil, types.ScanTarget{}, errors.New("SBOM has no specVersion")
	}

	var listed []cdx.Component
	var inventory []v0s.Component
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		root := bom.Metadata.Component
		listed = flatten(listed, root.Components)
		root.Components = nil
		if p, ok := fillPURL(root); ok && p.Type != packageurl.TypeOCI {
			c, err := component(root.Name, p)
			if err != nil {
				return nil, types.ScanTarget{}, err
			}
			inventory = append(inventory, c)
		}
	}
	listed = flatten(listed, bom.Components)
	for i := range listed {
		p, ok := fillPURL(&listed[i])
		if !ok {
			continue
		}
		c, err := component(listed[i].Name, p)
		if err != nil {
			return nil, types.ScanTarget{}, err
		}
		inventory = append(inventory, c)
	}
	bom.Components = &listed

	flat, err := json.Marshal(&bom)
	if err != nil {
		return nil, types.ScanTarget{}, fmt.Errorf("encoding flattened SBOM: %w", err)
	}
	decoded, err := sbom.Decode(ctx, bytes.NewReader(flat), sbom.FormatCycloneDXJSON)
	if err != nil {
		return nil, types.ScanTarget{}, fmt.Errorf("decoding SBOM: %w", err)
	}
	target := types.ScanTarget{Name: "sbom", Applications: decoded.Applications}
	if decoded.Metadata.OS != nil {
		target.OS = *decoded.Metadata.OS
	}
	for _, info := range decoded.Packages {
		target.Packages = append(target.Packages, info.Packages...)
	}
	return inventory, target, nil
}

// flatten appends cs and all components nested in them to dst, with their nesting removed.
func flatten(dst []cdx.Component, cs *[]cdx.Component) []cdx.Component {
	if cs == nil {
		return dst
	}
	for _, c := range *cs {
		nested := c.Components
		c.Components = nil
		dst = append(dst, c)
		dst = flatten(dst, nested)
	}
	return dst
}

// fillPURL parses the purl of c, takes its version from c.Version if the purl has none,
// and writes the purl back to c in canonical form. It reports false if c has no valid purl.
func fillPURL(c *cdx.Component) (packageurl.PackageURL, bool) {
	if c.PackageURL == "" {
		return packageurl.PackageURL{}, false
	}
	p, err := packageurl.FromString(c.PackageURL)
	if err != nil {
		return packageurl.PackageURL{}, false
	}
	if p.Version == "" && c.Version != "" {
		// Re-parse so the filled version is normalized and validated like one in the purl.
		withVersion := p
		withVersion.Version = c.Version
		if q, err := packageurl.FromString(withVersion.ToString()); err == nil {
			p = q
		}
	}
	c.PackageURL = p.ToString()
	return p, true
}

// component returns the inventory entry for a component named name with purl p.
func component(name string, p packageurl.PackageURL) (v0s.Component, error) {
	s := p.ToString()
	key, err := purl.PackageKey(s)
	if err != nil {
		return v0s.Component{}, fmt.Errorf("component %s: %w", s, err)
	}
	return v0s.Component{PURL: s, PackageKey: key, Name: name, Version: p.Version}, nil
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

// result maps the inventory and Trivy's vulnerabilities to v0s types, sorted and deduplicated.
func result(components []v0s.Component, vulns []types.DetectedVulnerability) (v0s.ScanResult, error) {
	var res v0s.ScanResult
	seen := make(map[string]bool)
	for _, c := range components {
		if !seen[c.PURL] {
			seen[c.PURL] = true
			res.Components = append(res.Components, c)
		}
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
