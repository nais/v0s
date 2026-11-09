# Verification before replacing v13s and Dependency-Track

Run in shadow mode: v0s has no consumers, and v13s/Dependency-Track remain
untouched. Start in dev-nais for behaviour; proceed to nav for scale only after
separate approval. Local tests do not establish production readiness.

Use a current v0s build, a compatible Nais API and the current schema; see
[Operations](operations.md). Update the [comparison tool](../tools/compare/README.md)
before using it. Record tenant, time, workload snapshot, image digests, v0s build
and Trivy DB version/digest with each result. Keep run-specific logs and outputs
out of the current design docs.

## Findings and coverage

- Compare findings on **image digest, package purl and canonical vulnerability
  ID**, not mutable tags or raw row counts. v0s lists one occurrence per workload;
  normalize aliases and keep unfixed findings separate from DT's filtered output.
- Classify every critical/high discrepancy by hand: v0s error, v13s/DT error, or
  defensible source difference. DT is not ground truth. No critical/high difference
  may remain unclassified.
- Compare workload coverage: applications scaled to zero, jobs between runs,
  unresolved image references, and images that are `PENDING`, `SCANNED`, `NO_SBOM`
  or `FAILED`. Platform workloads and sidecars are intentionally excluded.
- Search for a known package/version with findings and one without. Both should
  return the workloads using it.
- Set, replace, list and delete a suppression on a real finding. Verify the finding
  and counts change only for that team's workloads, including an image shared
  across teams. Verify the assessment survives a restart and database recovery.
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
dev-nais alone cannot establish nav-scale performance.

Before adding consumers:

- Verify the chart's required Fasit features are deployed, especially `nais-api`,
  and exercise its `Workloads.ListImages` contract. If Nais API consumes v0s
  findings, confirm its inventory endpoint and readiness work without v0s.
- For a new database, verify CNPG bootstraps `v0s-db`, supplies `v0s-db-app.uri`,
  and has enough eligible nodes/storage for the configured instances. Verify the
  database policies' Fasit-computed API/DNS addresses and actual app connectivity.
- For databases whose data must survive, set `postgresqlEnabled=false` before
  upgrading and verify the existing Cluster/PVC identities and suppressions.
  The disposable dev-nais pilot is explicitly approved for destructive reset:
  verify fresh Cluster/PVC identities, Helm ownership and successful bootstrap.
  That approval does not apply to NAV.
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
