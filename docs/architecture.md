# Architecture

v0s is a per-tenant vulnerability service built around Nais API's workload
inventory. It reports source facts and teams' assessments; it does not decide
which findings to prioritize. It is separately deployable, not independent of
Nais API.
See [CONTEXT.md](../CONTEXT.md) for identities and counting semantics, and the
[protobuf contract](../proto/v0s/v1/v0s.proto) for the API.

## Required Nais API dependency

Nais API owns workload discovery; v0s owns SBOM verification, vulnerability
matching and assessments for those workloads. Nais API's internal gRPC
`Workloads.ListImages` is the only inventory source. There are no direct
Kubernetes watches, cluster credentials or alternative inventory backends in
v0s. This is a deliberate simplification, not a missing integration.

The tradeoff is that inventory coverage and updates depend on Nais API. If it
is unavailable, v0s retains its stored inventory and results, continues rescanning
stored SBOMs, and retries discovery. `/healthz` does not test Nais API; operational
checks must observe inventory reconciliation separately.

Keeping v0s in a separate process isolates Trivy's dependencies, memory use and
scan failures from Nais API. If Nais API also consumes v0s findings, its inventory
endpoint must still work when v0s is unavailable. Neither its startup nor its
readiness may depend on v0s.

The [chart](../charts/README.md) declares `nais-api` as a required Fasit feature.
This is not a Helm subchart and does not install another Nais API instance.
A deployed feature does not prove gRPC compatibility: the Nais API build must
expose the `Workloads.ListImages` contract used by v0s.

## Data flow

```text
Nais API: deployed workload images
    → resolve tags to digests
    → fetch and verify attested CycloneDX SBOMs
    → match stored SBOMs against a local Trivy DB
    → Postgres: inventory, components, findings, suppressions
    → gRPC: findings, counts, package search, coverage, assessments

FIRST EPSS + CISA KEV → Postgres → finding enrichment
```

Nais API's internal `Workloads.ListImages` supplies applications and jobs,
including apps scaled to zero and jobs between runs. v0s needs no workload-cluster
credentials, RBAC or Pod watches. Platform workloads and injected sidecars are
outside the inventory.

Images are identified by repository name and digest. Tags are resolved once
while in use and cached per process. Moving a tag is not tracked; after a restart
or across replicas it may resolve differently. Unresolved references remain in
the inventory with an error rather than disappearing from coverage.

Verified SBOMs are stored for rescanning without registry access. Trivy runs
in-process against a local vulnerability DB; no images are pulled. Only
`internal/scan` imports Trivy. This avoids a separate scanner service, at the cost
of Trivy's large module graph and unstable internal APIs.

## Reconciliation, not a queue

Loops compare stored state with work still to do. PostgreSQL advisory locks
serialize inventory sync, SBOM fetching, scanning and enrichment across replicas;
scanning is serial, while fetches run in batches. Each replica downloads its own
Trivy DB and can serve the API.

| Loop | Work | Interval after a successful pass |
|---|---|---|
| Sync | Replace each reported environment's inventory; delete unused images | 1 minute |
| Fetch | Drain due SBOM fetches | 10 seconds |
| Scan | Drain images not processed with the loaded DB or newer | 10 seconds |
| Vulnerability DB | Check for a newer local Trivy DB | 1 hour |
| Enrichment | Replace EPSS and KEV source data | 24 hours |

A failed inventory request preserves stored workloads. Environments omitted from
a snapshot keep their previous inventory; an included, empty environment clears
it. Images no workload uses are deleted with their SBOMs, components and findings.

Already processed images are not repeatedly scanned with the same DB. New images
and newer DBs make work due. There is no scanner-version invalidation mechanism;
a code upgrade alone does not force a rescan. Concrete upgrade needs are handled
when they arise. Retry and failure behaviour is described in [Operations](operations.md).

## Stored facts and human assessments

`cmd/v0s` wires the service together. Private Go packages, including the shared
domain types in `internal/v0s`, live under `internal/`; the generated public
gRPC client stays in `api/v0s/v1`. There is one Go module.

`internal/database` owns hand-written SQL and embedded, numbered migrations
applied by `v0s migrate` under an advisory lock using the database owner. The
service uses a separate read/write role, checks the schema version on startup
and does not perform DDL. The chart stops old replicas before the migration
init container runs. Postgres holds shared application state; each
replica's Trivy DB is a replaceable local cache.

Findings are listed and counted per workload. Severity and fix information come
from the advisory source; EPSS and KEV come from FIRST and CISA without our own
thresholds or scoring. Components are searchable even when they have no findings.
No finding history, trends or first-seen timestamps are kept.

`ListFindings` and `CountFindings` accept `FindingFilter.package_type`, such as
`npm`, `maven` or `golang`. It is case-insensitive and combines with the other
filters using AND, including the existing exact-purl/package-key filter.
An empty type does not filter; unknown types match nothing. Malformed types
return `InvalidArgument`, like malformed values of the `package` filter.

The public read contract accepts one team or the whole tenant. A workload name
requires a team and environment. CVSS details are a versioned list per source on
the advisory, with optional scores/vectors instead of a versionless maximum on
every finding. CISA KEV is catalog membership, not exploitability. Until a
nonempty catalog has been imported, reads that expose or filter on membership
fail with `Unavailable`; a failed refresh retains the last valid catalog.
EPSS and KEV refreshes are independent. See
[contract rollout requirements](operations.md#simplified-public-contract).

Suppressions are keyed by team, environment, workload name, image name,
versionless package key and canonical vulnerability ID. They survive package
versions and image builds within that workload and repository. No other workload
or environment inherits them. Setting replaces the current assessment; deleting
removes it. There is no expiry or assessment history in v0s.

Clients discover other affected workloads using `ListFindings` with a
vulnerability ID or alias, optionally a package filter, and `suppressed=INCLUDE`.
`CountFindings` with `GROUP_BY_WORKLOAD` provides distinct workload buckets when
only identities/counts are needed. Neither query needs an image filter.
Clients explicitly select targets and call `SetSuppressions` with one key per
workload/image/package/vulnerability. Each batch is atomic within one authorized
team; cross-team operations require separate authorization and requests.
`ListSuppressions` can filter by environment and workload. These are service
capabilities, not an implemented Console workflow.

Inventory and scan results can be rebuilt; suppressions cannot. They are durable
human assessments owned here and require backup and recovery.

The deployment chart uses the shared `nais-postgresql` subchart to provision a
CNPG database for new installations; `cloudnative-pg` remains a required Fasit
operator feature. Existing databases can remain independently managed with
`postgresqlEnabled=false`. Managed Clusters are retained on Helm uninstall by
default, but that is not independent release ownership or backup protection.
The shared subchart does not configure backups. See [Operations](operations.md)
for the existing dev-nais database boundary and rollout requirements.

## Trust and current-state contract

The gRPC API has no authentication. NetworkPolicy restricts access to trusted
services in `nais-system`. Reads are tenant-wide; team filters are not access
control. Callers authorize suppression writes and supply team and actor. Any
permitted caller can therefore write assessments as any team.

Clients use v0s's stored results as its current view. They do not manage inventory
age, a target DB version or a stale-state protocol. Updating results and handling
delays is v0s's operational responsibility, not a guarantee of instantaneous scan
completion. Coverage states and errors remain visible; zero findings do not
establish complete coverage or the absence of vulnerabilities.
