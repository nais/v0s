const common = `
You implement one lane of a new Go service, nais/v0s. The repo is your cwd (a git worktree of /Users/hrv/ws/github.com/nais/v0s, branched from main).

Before writing code, read in full: README.md, CONTEXT.md, docs/adr/0001-core-decisions.md, v0s.go, internal/database/database.go, internal/database/databasetest/databasetest.go, internal/database/migrations/0001_schema.sql, proto/v0s/v1/v0s.proto, internal/purl/purl.go. Then read and strictly follow /Users/hrv/.pi/agent/skills/go-dev/SKILL.md.

Hard rules:
- Minimal and deliberate. Write only what your contract below needs. No speculative abstractions, no config knobs that nobody sets, no metrics, no interfaces with a single implementation unless a test fake needs them, no util/common packages.
- Use log/slog. Wrap errors with context. No panics. Every goroutine has an owner and a stop signal.
- Tests check the package's contract, not its implementation branches. Write a few meaningful table-driven tests with the standard library, and no assertion libraries. Do not over-test.
- Postgres tests use databasetest.Main/New. Run tests with env V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin.
- Stay within your edit boundary. Do NOT change v0s.go, the migration, the proto, generated code, or other lanes' packages. If the contract is wrong or insufficient, still implement the closest correct thing, and list the needed contract change under "Contract issues" in your final report. Do not silently work around it.
- Add dependencies with go get at sensible pinned versions; run go mod tidy.
- Validation gate, all must exit 0 (check the real exit codes, do not pipe): gofmt -l . (prints nothing), go build ./..., go vet ./..., go tool staticcheck ./..., V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin go test -race ./...
- When the gate passes, commit everything on your worktree branch with one descriptive commit.

Final report (concise): what you built (exported API with signatures), notable decisions and why, contract issues, known gaps, and gate results with the exact commands.
`;

const scan = `
LANE: internal/scan, matching with Trivy as a Go library. Edit boundary: internal/scan/** (including testdata), go.mod, go.sum.

Only this package may import github.com/aquasecurity/trivy (use v0.76.1) or trivy-db. trivy-db keeps a process-global bolt handle (pkg/db Init/Close in trivy-db). This package owns it.

Contract:
  // Scanner matches SBOMs against a local Trivy vulnerability DB and keeps that DB up to date.
  type Scanner struct{ ... }
  // New loads the DB in dir if one is present. repos are OCI refs for trivy-db, tried in order,
  // e.g. "mirror.gcr.io/aquasec/trivy-db:2", "ghcr.io/aquasecurity/trivy-db:2".
  func New(dir string, repos []string, log *slog.Logger) (*Scanner, error)
  // Update downloads a newer DB if the registry has one and swaps it in atomically. If the
  // download or validation fails, the loaded DB stays in use. Returns whether it swapped.
  func (s *Scanner) Update(ctx context.Context) (bool, error)
  // DBVersion is the UpdatedAt of the loaded DB, or zero if none is loaded.
  func (s *Scanner) DBVersion() time.Time
  // Scan matches a CycloneDX JSON SBOM and returns the result and the DB version it used.
  // Returns ErrNoDB if no DB is loaded.
  func (s *Scanner) Scan(ctx context.Context, sbom []byte) (v0s.ScanResult, time.Time, error)
  var ErrNoDB = errors.New(...)

Requirements:
- Scans take a read lock and the DB swap takes the write lock, so a scan never sees a closed or half-swapped DB. Download into a fresh directory under dir, validate it (metadata readable, schema version supported), then swap: close the old one, init the new one, and remove the old directory. On startup, New picks up the newest valid DB under dir and cleans up leftovers.
- Do not touch Trivy's Java DB. SBOM scanning does not need it. Verify this claim by reading Trivy's code path. If it is false, report it.
- Decode with trivy pkg/sbom (CycloneDX JSON), build a types.ScanTarget (OS, Packages, Applications), and run pkg/scan/local Service.ScanTarget (or the narrowest equivalent) with vulnerability scanning for OS and library packages. Use default detection priority (precise). Do NOT ignore unfixed findings.
- Map to v0s types:
  - Components: every package that has a purl, with PackageKey from internal/purl, Name and Version. Skip packages without a purl. Deduplicate by purl.
  - Findings: VulnerabilityID, PURL of the affected package, PackageKey, InstalledVersion, FixedVersion, Status (Trivy's status string, lowercase, e.g. "affected", "fixed", "will_not_fix"), Severity (UPPERCASE as in v0s constants), SeveritySource, DataSource (the DataSource.ID). Deduplicate by (VulnerabilityID, PURL).
  - Vulnerabilities: one per referenced ID, with Title, Description, Severities by source (VendorSeverity), CVSS by source (V3Vector/V3Score/V40Vector/V40Score), References, PublishedAt and ModifiedAt, and Aliases from VendorIDs (excluding the ID itself).
- Route Trivy's own logging to the slog logger or discard it. Do not leave Trivy printing to stdout. Do not mutate other Trivy globals.
- Registry access: anonymous works for public mirrors. Also allow ambient Google credentials for Artifact Registry if Trivy's RegistryOptions supports it cheaply. Do not build a credentials system.
- Tests: build a tiny fixture DB in testdata (or at test time) the way Trivy's own internal/dbtest does, with bolt fixtures and trivy-db schema. Include at least one OS advisory (Alpine) and one language advisory (npm, GHSA), plus a small CycloneDX SBOM with an alpine OS package, an npm package, and one package without a purl. Assert the Scan contract: components, findings fields, vulnerabilities with aliases, and the returned DB version. Test Update only if you can do it in under about 80 lines with an in-process OCI registry (go-containerregistry pkg/registry). Otherwise report it as a gap. Run -race with concurrent Scan and swap if feasible within the same budget.
`;

const write = `
LANE: write path of the store. Edit boundary: new files internal/database/images.go, internal/database/scans.go, internal/database/workloads.go, internal/database/enrich.go, internal/database/lock.go, and their _test.go files. Also go.mod and go.sum. Do not edit database.go except to add a line if truly unavoidable (report it).

Use pgx v5 (already a dependency) and hand-written SQL. Every statement is parameterized.

Contract (methods on *database.DB):
  // SyncWorkloadImages makes ws the complete set of workload images for cluster. It creates
  // missing images (sbom_state pending), bumps last_seen_at for every image in ws, and replaces
  // the cluster's workload_images rows. Atomic.
  func (db *DB) SyncWorkloadImages(ctx context.Context, cluster string, ws []v0s.WorkloadImage) error
  // ClaimSBOMFetches returns up to limit images that are in use (referenced by workload_images),
  // not fetched, and due (sbom_next_attempt_at <= now()). It leases them by moving
  // sbom_next_attempt_at to now()+lease. Concurrent callers never get the same image (SKIP LOCKED).
  func (db *DB) ClaimSBOMFetches(ctx context.Context, limit int, lease time.Duration) ([]v0s.Image, error)
  // StoreSBOM stores the verified SBOM (gzip-compressed) and marks the image fetched.
  func (db *DB) StoreSBOM(ctx context.Context, imageID int64, document []byte) error
  // RecordSBOMFailure marks the image missing or failed with a message and the next attempt time.
  func (db *DB) RecordSBOMFailure(ctx context.Context, imageID int64, state v0s.SBOMState, msg string, retryAt time.Time) error
  type ScanJob struct { Image v0s.Image; SBOM []byte } // SBOM decompressed
  // ClaimScans returns up to limit in-use, fetched images whose scanned_db_version is null or older
  // than dbVersion, and whose scan lease has expired. Leases them for lease.
  func (db *DB) ClaimScans(ctx context.Context, dbVersion time.Time, limit int, lease time.Duration) ([]ScanJob, error)
  // StoreScan records a scan result. If the image already has scanned_db_version >= dbVersion it is
  // a no-op. Otherwise, in one transaction: upsert vulnerabilities and their aliases, write
  // finding_events (appeared for new (vulnerability_id, purl) pairs, resolved for vanished ones),
  // replace findings while preserving first_seen_at for findings that persist, insert components
  // if the image has none (SBOMs are immutable), set scanned_db_version and scanned_at, clear
  // scan_error and the lease.
  func (db *DB) StoreScan(ctx context.Context, imageID int64, dbVersion time.Time, r v0s.ScanResult) error
  // RecordScanFailure sets scan_error and scanned_db_version = dbVersion, so the same DB is not
  // retried in a hot loop, and clears the lease.
  func (db *DB) RecordScanFailure(ctx context.Context, imageID int64, dbVersion time.Time, msg string) error
  // ReplaceEPSS and ReplaceKEV atomically replace the table contents. EPSS has about 300k rows:
  // use COPY into a temp table, then swap within one transaction.
  func (db *DB) ReplaceEPSS(ctx context.Context, scores []v0s.EPSS) error
  func (db *DB) ReplaceKEV(ctx context.Context, entries []v0s.KEV) error
  // DeleteUnusedImages deletes images not referenced by workload_images whose last_seen_at is older
  // than unusedFor. Cascades to SBOMs, components and findings. Finding events are kept.
  func (db *DB) DeleteUnusedImages(ctx context.Context, unusedFor time.Duration) (int64, error)
  // WithLock runs fn if it can take the named cluster-wide advisory lock, and reports whether fn ran.
  // Used for singleton jobs (enrichment, GC).
  func (db *DB) WithLock(ctx context.Context, name string, fn func(ctx context.Context) error) (bool, error)

Notes: findings.vulnerability_id references vulnerabilities, so upsert vulnerabilities first. Vulnerability severities and cvss are jsonb maps (see v0s.CVSS json tags). Images map to v0s.Image, with zero times for NULLs. Keep the SQL readable. Use large batches efficiently (COPY or unnest arrays) without being clever.

Tests (Postgres, black-box package database_test): workload sync replaces the snapshot and creates pending images. Claims exclude images not in use or not due and respect leases. Two concurrent claimers get disjoint sets. StoreScan produces the right appeared/resolved events across two scans, preserves first_seen_at, and is a no-op for an older or equal dbVersion. ReplaceEPSS is atomic. DeleteUnusedImages keeps in-use images. Keep the tests compact.
`;

const read = `
LANE: read path, suppressions, gRPC API and auth. Edit boundary: new files internal/database/findings.go, internal/database/suppressions.go, internal/database/workloads_read.go, internal/database/components.go (plus _test.go), new packages internal/grpcapi/** and internal/auth/**, and go.mod/go.sum.

Another lane is concurrently writing the store's write path (images.go, scans.go, workloads.go, enrich.go, lock.go). Do not create files with those names. Seed test data with plain SQL inside same-package tests (package database, using db.pool). If grpcapi tests need seeding, they may seed with pgx through a connection URL. For that you may add one minimal exported helper to databasetest.go, for example func NewWithURL(t) (*database.DB, string). Report it.

Implement both services in proto/v0s/v1/v0s.proto (generated Go is in api/v0s/v1, package v0sv1):
- grpcapi.New(db *database.DB, log *slog.Logger) returns a type implementing v0sv1.VulnerabilityServiceServer and v0sv1.SuppressionServiceServer, plus a func Register(s *grpc.Server, ...) or equivalent. Keep it plain.
- Database read methods are yours to design. They take a filter struct and return v0s types or small structs. The proto mapping lives in grpcapi. Use dynamic SQL built from a fixed set of parameterized clauses, never string-interpolated values.
- Semantics, binding:
  - "In use" means referenced by workload_images. ListFindings, CountFindings and SearchComponents only consider images in use. Namespace, cluster and workload filters join through workload_images.
  - Suppression matching: a finding is suppressed by the active suppression with image_name = images.name, package_key = findings.package_key and vulnerability_id = findings.vulnerability_id. Active means revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()). SuppressedFilter UNSPECIFIED means EXCLUDE.
  - vulnerability_id filter and GetVulnerability accept an ID or an alias.
  - package filter: if the value parses as a purl with a version, match findings.purl exactly. Otherwise match package_key (normalize with internal/purl).
  - cvss_score is the max v3_score across sources in vulnerabilities.cvss. EPSS and KEV join on the finding's vulnerability_id = cve.
  - Pagination: opaque page_token. Default page_size 100, max 1000. Keyset on a stable unique order where practical. Offset is acceptable only for CountFindings and SearchComponents if keyset is awkward. Say which you used.
  - CountFindings requires group_by (InvalidArgument otherwise). Keys are as documented in the proto. Counting a finding once per workload under WORKLOAD and NAMESPACE grouping is correct, since an image can run in several workloads. Document the behavior in a comment.
  - CreateSuppressions is all or nothing, in one transaction. Per item: normalize the package with purl.PackageKey. Resolve vulnerability_id: an exact ID in vulnerabilities, otherwise exactly one alias match, else InvalidArgument naming the item index. Validate state and justification (justification required for NOT_AFFECTED, forbidden otherwise), non-empty detail and actor, and expires_at in the future if set. If an unrevoked row exists for the key, revoke it (revoked_by = actor, revoke_reason = "replaced by suppression <new id>" or "expired" if it had expired) and set replaces_id when it was active. Count matched_findings as current findings on in-use images matching the key. dry_run does everything, then rolls back, and returns results with id 0. Duplicate keys within one request are InvalidArgument.
  - RevokeSuppressions is atomic. Unknown or already revoked IDs give NotFound/FailedPrecondition naming the ID. Requires actor and reason.
  - ListSuppressions: active only unless include_inactive. Filter by image_name and vulnerability_id (ID or alias).
  - ListWorkloads groups workload_images into workloads with containers and image facts.
  - ListFindingEvents filters by image name/digest, vulnerability ID/alias, and namespace (events whose image name+digest currently runs in the namespace), and since. Ordered by id, keyset.
- Errors map to proper gRPC codes. Never leak SQL errors to clients. Log them with slog and return Internal.
- internal/auth: a gRPC unary interceptor that verifies a Google-signed ID token (google.golang.org/api/idtoken) from the "authorization: Bearer" metadata, checks the audience, and checks that the email claim is in an allowlist. Port the behavior of /Users/hrv/ws/github.com/nais/v13s/internal/api/auth (read it with git show origin/main:<path> if needed). Constructor parameters only, no env reading. Unit-test the decision logic with a fake validator.
- Tests: a compact set of Postgres-backed tests over the database methods or through the gRPC handlers. Cover suppression matching (active, expired, revoked, version bump still suppressed), CreateSuppressions (alias resolution, replacement, dry-run writes nothing, atomic failure), package and alias filters, and pagination continuity. Do not test proto field copying exhaustively.
`;

const edge = `
LANE: edges, meaning Kubernetes watching, SBOM attestation fetching and enrichment feeds. Edit boundary: new packages internal/kube/**, internal/attest/**, internal/enrich/**, and go.mod/go.sum.

1. internal/kube: watch pods in several clusters with client-go shared informers.
  type Watcher struct{...}
  // NewWatcher creates informers for pods in every cluster. clusters maps cluster name to rest config.
  func NewWatcher(clusters map[string]*rest.Config, log *slog.Logger) (*Watcher, error)
  // Run starts the informers and blocks until ctx is done.
  func (w *Watcher) Run(ctx context.Context) error
  // Clusters lists the watched cluster names.
  func (w *Watcher) Clusters() []string
  // Snapshot returns the workload images currently observed in cluster, and false if the cluster's
  // informer has not synced (callers must not treat an unsynced snapshot as truth).
  func (w *Watcher) Snapshot(cluster string) ([]v0s.WorkloadImage, bool)
  // ClusterConfigs builds rest configs for Nais clusters: remote clusters at
  // https://apiserver.<cluster>.<tenant>.cloud.nais.io using Google credentials, and the in-cluster
  // config for selfCluster if set.
  func ClusterConfigs(tenant string, clusters []string, selfCluster string) (map[string]*rest.Config, error)
 Rules: only pods with an "app" label. Workload = app label, namespace = pod namespace. For every container status (regular containers only, not init or ephemeral) with a non-empty imageID, parse the image name (repository) and digest from status.imageID. Accept forms like "docker-pullable://repo@sha256:...", "repo@sha256:..." and "sha256:..."; when only a digest is present, take the repository from status.image without its tag. Pods in any phase count while they exist, so recently completed job pods count too. OwnerKind = kind of the controller ownerReference, else "". Deduplicate. Use an informer transform to strip pods down to the needed fields, so memory stays low for large clusters. Port the Google auth approach from /Users/hrv/ws/github.com/nais/v13s internal/config (git show origin/main:internal/config/config.go and any related files): find how GoogleAuthPlugin is provided and do the simplest correct equivalent (for example golang.org/x/oauth2/google token source via WrapTransport) instead of a registered auth plugin if that is simpler.
 Test the snapshot rules with the client-go fake clientset: label filtering, imageID parsing table, owner kind, dedup.

2. internal/attest: fetch and verify cosign attestations.
  type Fetcher struct{...}
  // NewFetcher verifies attestations signed by GitHub Actions workflows in the given GitHub organizations.
  func NewFetcher(organizations []string, log *slog.Logger) (*Fetcher, error)
  // Fetch returns the verified CycloneDX JSON SBOM attested to ref ("repo@sha256:..."). It returns
  // ErrNotFound if the image has no matching attestation.
  func (f *Fetcher) Fetch(ctx context.Context, ref string) ([]byte, error)
  var ErrNotFound = errors.New(...)
 Port the verification semantics from v13s (git show origin/main:internal/attestation/attestation.go, internal/attestation/github/github.go in /Users/hrv/ws/github.com/nais/v13s): cosign v3 VerifyImageAttestations with the trusted root, the new bundle format, the GitHub OIDC issuer and subject regexp for the orgs, and the keychain default+google+github. Select the CycloneDX predicate (predicateType https://cyclonedx.org/bom) from the in-toto statement and return the predicate JSON exactly. Do not port the Rekor metadata, compression, or the logrus/error-classification machinery. Map "no matching attestations" and registry 404 MANIFEST_UNKNOWN to ErrNotFound. Return other errors wrapped. Test only the identity regexp (orgs are escaped, workflows under .github/workflows only) and predicate selection from a static in-toto statement in testdata. Do not do network tests.

3. internal/enrich: parse public feeds.
  // FetchEPSS downloads and parses the daily FIRST EPSS CSV (gzip). url defaults are the caller's
  // concern. Expose the current official URL as a constant DefaultEPSSURL; verify the URL is current.
  func FetchEPSS(ctx context.Context, c *http.Client, url string) ([]v0s.EPSS, error)
  // FetchKEV downloads and parses the CISA KEV JSON feed. Constant DefaultKEVURL.
  func FetchKEV(ctx context.Context, c *http.Client, url string) ([]v0s.KEV, error)
 Parse the EPSS header comment line for the score date (model_version and score_date). Reject an empty feed with an error, so a broken upstream never wipes the tables. Test the parsers with small testdata files through httptest. Verify the feed URLs and formats with a single curl each (headers or the first bytes only).
`;

const results = await runs.all([
  { key: "scan", label: "Implement Trivy scanner package", agent: "worker", task: common + scan, worktree: true },
  { key: "write", label: "Implement store write path", agent: "worker", task: common + write, worktree: true },
  { key: "read", label: "Implement read API and suppressions", agent: "worker", task: common + read, worktree: true },
  { key: "edge", label: "Implement kube, attest, enrich", agent: "worker", task: common + edge, worktree: true },
]);
return results.map((r) => ({ key: r.key, status: r.status, output: r.output, artifacts: r.artifactPaths }));
