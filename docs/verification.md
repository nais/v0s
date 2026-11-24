# Verification before replacing v13s and Dependency-Track

Before cutover, run verification in shadow mode without moving consumers or
changing v13s/Dependency-Track. Start in a development tenant for behaviour;
proceed to a production-scale tenant only after separate approval. This is an
acceptance checklist, not a record of completed checks. Local tests and
historical pilot results do not establish production readiness.

Use a current v0s build, a compatible Nais API and the current schema; see
[Operations](operations.md). Update the [comparison tool](../tools/compare/README.md)
before using it. Record tenant, time, workload snapshot, image digests, v0s build
and Trivy DB version/digest with each result. Keep run-specific logs, workload
inventories and detailed results in access-controlled storage, not in Git.

## Findings and coverage

- Compare findings on **image digest, package purl and canonical vulnerability
  ID**, not mutable tags or raw row counts. v0s lists one occurrence per workload;
  normalize aliases and keep unfixed findings separate from DT's filtered output.
- Classify every critical/high discrepancy by hand: v0s error, v13s/DT error, or
  defensible source difference. DT is not ground truth. No critical/high difference
  may remain unclassified.
- Distinguish missing source advisories, deliberate catalog policy and matcher
  errors. A catalog of fixed OS advisories may omit pending vendor records;
  that does not mean the scanner generally ignores unfixed vulnerabilities.
  Include withdrawn advisories and incorrect package attribution in the review.
- Pin the scanner and database versions. Prefer identical original attested
  SBOMs for matcher comparisons; exported or regenerated SBOMs may differ.
  A direct image scan evaluates inventory generation as well as matching.
  Mark non-atomic snapshots and changes during collection explicitly.
  Overlap with another system is not recall, correctness or a cutover threshold.
- Compare workload coverage: applications scaled to zero, jobs between runs,
  unresolved image references, and images that are `PENDING`, `SCANNED`, `NO_SBOM`
  or `FAILED`. Platform workloads and sidecars are intentionally excluded.
- Search for a known package/version with findings and one without. Both should
  return the workloads using it.
- Set, replace, list and delete a suppression on a real finding. Verify the finding
  and counts change only for the selected environment/team/workload, including
  an image shared by apps and jobs in the same team and across teams/environments.
  Discover other affected workloads with suppressed findings included, explicitly
  batch-assess selected workloads, and verify unselected workloads are unchanged.
  Verify the assessment survives a rebuild, restart and database recovery.
  Check migration counts and unmatched records in `legacy_suppressions`.
- On upgrade, retain Cluster/PVC identities and verify the migration init
  container completes before runtime starts. Runtime must use the read/write
  role, not the owner, and must be unable to create or alter permanent tables.
  Keep the database and owner unchanged; do not reset data to apply migrations.
  Verify that Fasit/Helm automatic rollback cannot restart an incompatible old
  binary against a migrated schema; a live scale-to-zero is not a saved rollback
  revision.
- Measure source-SBOM gaps: missing OS packages and runtime binaries. A successful
  scan with zero findings is not a completeness or safety claim.

## Reconciliation and failures

| Scenario | Expected |
|---|---|
| Deploy a new tag or digest | New image appears and is processed; the old image is removed if unused |
| Move an existing tag | No update is expected; mutable-tag tracking is outside scope |
| Delete a workload | Its unused image, SBOM, components and findings are removed at the next sync |
| Nais API is unavailable or omits an environment | Previous inventory is retained; reads and stored-SBOM rescans remain available, and inventory sync retries |
| Image has no attestation | `NO_SBOM`; retry after backoff, no retry storm |
| Newer Trivy DB loads | In-use images become due for rescanning without any client action |
| Scan fails | Error is visible; previous findings remain; retry on a newer DB |
| Two replicas | Both serve reads; each worker loop is serialized across replicas |
| Kill a pod during scanning | Work resumes without lost results; persistent crashers hit the attempt cap |
| Database restart or registry/feed outage | Loops log failures and retry; committed data remains |

Check scan counts during a stable-inventory, successful rescan: already processed
images should not be repeatedly scanned with the same DB. During a failure test,
repeated attempts are expected. `/healthz` reflects database connectivity only;
check loop logs, coverage and metrics separately.

## Scale and deployment boundary

Measure cold-start backlog clearance, full-rescan duration, scan p50/p99, peak
memory, CPU, PostgreSQL IO and size/growth, and gRPC latency for findings, counts
and package search. Judge the measurements before expanding the rollout;
a small development tenant alone cannot establish production-scale performance.
Separate resource requests and limits from observed use; neither configured
reservations nor an idle snapshot proves equal capacity or availability.
Include application replicas and databases when comparing deployment footprints.

Before adding consumers:

- Verify the chart's required Fasit features are deployed, especially `nais-api`,
  and exercise its `Workloads.ListImages` contract. If Nais API consumes v0s
  findings, confirm its inventory endpoint and readiness work without v0s.
- For a new database, verify CNPG bootstraps `v0s-db`, supplies `v0s-db-app.uri`,
  and has enough eligible nodes/storage for the configured instances. Verify the
  platform's `nais-netpols-management` DNS/API egress and actual app connectivity;
  v0s does not require per-cluster CIDR values.
- For an existing independently managed database, use `postgresqlEnabled=false`
  and verify the existing Cluster/PVC identities and suppressions. For a
  chart-managed database, preserve its release ownership and data during upgrade.
  Do not reset a database to apply migrations. Any destructive test requires
  separate approval for a specifically identified disposable environment.
- Verify a packaged release includes its database dependency and works without
  fetching subcharts from the target cluster. Verify managed Cluster retention
  on uninstall/reinstall in a disposable environment, not a real tenant database.
- Verify the dedicated runtime identity, CNPG connection secret, writable cache
  volumes and egress against the tenant's actual registries and redirects.
- Verify NetworkPolicy admits only intended trusted callers. Confirm callers
  authorize suppression writes; the service itself trusts their team and actor.
- Establish database backup and restore, preserving suppressions.
- Review attestation identity limitations and remaining integration items in
  [Operations](operations.md).
- Map consumer assessment states explicitly. Suppression migration from v13s is
  separate work, not an implicit part of the comparison.
