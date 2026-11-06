// Package v0s holds the domain types shared across the service. It has no third-party dependencies.
//
// Types are plain facts as v0s records them; see CONTEXT.md for the vocabulary.
package v0s

import "time"

// Severity as reported by the vulnerability DB.
type Severity string

// Severities, from least to most severe.
const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// SBOMState tracks whether an image's attested SBOM has been fetched.
type SBOMState string

// SBOM states.
const (
	SBOMPending SBOMState = "pending"
	SBOMFetched SBOMState = "fetched"
	SBOMMissing SBOMState = "missing"
	SBOMFailed  SBOMState = "failed"
)

// Image is a container image identified by repository name and manifest digest.
type Image struct {
	ID               int64
	Name             string
	Digest           string
	SBOMState        SBOMState
	ScannedAt        time.Time // zero if never scanned
	ScannedDBVersion time.Time // zero if never scanned
	// Error says why the last fetch or, once fetched, the last scan failed.
	Error string
}

// Ref returns the image reference by digest, e.g. "repo/name@sha256:…".
func (i Image) Ref() string { return i.Name + "@" + i.Digest }

// ImageStatus is how far an image has got towards having findings.
type ImageStatus string

// Image statuses.
const (
	ImagePending ImageStatus = "pending" // SBOM not fetched or image not scanned yet
	ImageScanned ImageStatus = "scanned"
	ImageNoSBOM  ImageStatus = "no_sbom" // no attested SBOM found
	ImageFailed  ImageStatus = "failed"  // fetching, verifying or scanning failed
)

// Status returns how far the image has got. A scanned image stays scanned when a rescan with a
// newer DB fails; Error then says why.
func (i Image) Status() ImageStatus {
	switch {
	case i.SBOMState == SBOMMissing:
		return ImageNoSBOM
	case i.SBOMState == SBOMFailed:
		return ImageFailed
	case i.SBOMState != SBOMFetched:
		return ImagePending
	case !i.ScannedAt.IsZero():
		return ImageScanned
	case i.Error != "":
		return ImageFailed
	default:
		return ImagePending
	}
}

// WorkloadImage records the image a workload is deployed with.
type WorkloadImage struct {
	Environment string
	Team        string
	Workload    string
	// Reference is the image as deployed, e.g. "ghcr.io/navikt/app:1.2.3".
	Reference string
	// ImageName and Digest identify the image Reference resolved to. Both are empty if it could
	// not be resolved, and ResolveError says why.
	ImageName    string
	Digest       string
	ResolveError string
}

// Component is a package listed in an SBOM.
type Component struct {
	PURL       string
	PackageKey string
	Name       string
	Version    string
}

// Finding is a vulnerability affecting one component, according to one DB version.
type Finding struct {
	VulnerabilityID  string
	PURL             string
	PackageKey       string
	InstalledVersion string
	FixedVersion     string
	Status           string
	Severity         Severity
	SeveritySource   string
	DataSource       string
}

// CVSS scores from one source.
type CVSS struct {
	V3Vector  string  `json:"v3_vector,omitempty"`
	V3Score   float64 `json:"v3_score,omitempty"`
	V40Vector string  `json:"v40_vector,omitempty"`
	V40Score  float64 `json:"v40_score,omitempty"`
}

// Vulnerability is a vulnerability record from the DB.
type Vulnerability struct {
	ID          string
	Aliases     []string
	Title       string
	Description string
	Severities  map[string]Severity // by source
	CVSS        map[string]CVSS     // by source
	References  []string
	PublishedAt time.Time // zero if unknown
	ModifiedAt  time.Time // zero if unknown
}

// ScanResult is the outcome of matching one SBOM against one DB version.
type ScanResult struct {
	Components      []Component
	Findings        []Finding
	Vulnerabilities []Vulnerability // every vulnerability referenced by Findings
}

// EPSS is a FIRST EPSS score for one CVE.
type EPSS struct {
	CVE        string
	Score      float64
	Percentile float64
	Date       time.Time
}

// KEV is a CISA Known Exploited Vulnerabilities entry.
type KEV struct {
	CVE                     string
	DateAdded               time.Time
	DueDate                 time.Time // zero if none
	KnownRansomwareCampaign bool
}
