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

The choice reuses the existing attested CycloneDX input rather than introducing
another image-scanning pipeline. Matching quality still depends on both that
input and Trivy's source catalog. Differences from Dependency-Track are not all
false positives or all missed vulnerabilities; they require source-level review.
See the [verification method](verification.md#findings-and-coverage) and
[source-contract considerations](utviklerkontrakt.md#kildeavgrensninger).

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
gRPC client stays in `api/v0s/v1`. There are two Go modules: the server at the
root and the lightweight `github.com/nais/v0s/api` client under `api/`.
The server uses `replace github.com/nais/v0s/api => ./api`, so both server and
external clients use code generated from the same authoritative protobuf.
The client has no server or Trivy dependency. See the
[client release instructions](../README.md#go-client).

`internal/database` owns hand-written SQL so optional read filters remain
explicit alongside the code that uses them. Embedded, numbered migrations are
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

`ListFindings` returns `package_type_counts` in byte order, derived from the
matching package keys. All active filters apply, including `package_type`
and suppression. Counts cover the full filtered result, not just the current
page, and count a finding once per workload using its image. The page and counts
come from the same database snapshot. Per-finding `cursors` remain available
alongside the counts; resuming from a cursor does not narrow the counts to the
remaining findings.

Finding ordering and its keyset boundary are applied in SQL before LIMIT.
Omitting `order_by` preserves environment/team/workload/vulnerability-ID/purl
ascending order. Explicit severity ordering always places UNKNOWN last, with
vulnerability ID ascending within a severity. Explicit vulnerability-ID ordering
supports both directions. Both explicit modes use environment/team/workload/purl
ascending to break remaining ties.

Finding cursors contain a version, a normalized filter/order fingerprint and
the boundary's ordering values. They require no lookup of the boundary finding,
so deletion does not prevent continuation. They are generated once per returned
finding, including on the last page. Legacy/incompatible versions and changed
filters/orders are `InvalidArgument`, requiring a restart without a token.
Page size is not bound. Filters normalize set-valued lists, package type and
purl spelling; alias-to-ID substitutions remain filter changes. There is no
cross-request snapshot: concurrent changes to sort values can move findings.
See the [gRPC continuation example](../README.md#finding-ordering-and-pagination).

`ListVulnerabilities` reuses the same finding joins, normalized filters and cursor
helpers. SQL filters occurrences before grouping by canonical vulnerability ID.
Each group has COUNT(*) findings, COUNT(DISTINCT (environment, team, workload
name)) affected workloads, and the highest known matching severity using semantic
CASE ranks, not CVSS or lexical severity order. Aliases filter canonical IDs
without multiplying occurrences. No advisory data is copied into summaries;
`GetVulnerability` remains the detail endpoint.

SQL applies keyset seek, sorting and LIMIT after aggregation. The default is
severity DESC, with UNKNOWN last in either direction. Additional sorts are
canonical ID and affected workload count, ASC/DESC; severity/count ties use ID
ASC. Identifier ordering and seek use bytewise, case-sensitive `COLLATE "C"`,
not natural numeric order. A separate count of the filtered groups, in the same
read-only repeatable-read transaction, supplies the total even on empty pages.

Overview cursors have a separate operation/version and store the boundary ID
and sort-specific aggregate values. They bind the effective order and normalized
filter, not page size, and do not look up the boundary row. Omitted order equals
explicit severity DESC. Invalid or incompatible tokens return `InvalidArgument`.
There is no snapshot across requests: group severity/count changes can move rows
and totals may change. KEV availability is checked only when the KEV filter is
active, since summaries do not expose KEV membership. See the
[overview contract and example](../README.md#vulnerability-overview).

`ListWorkloads` has an additive, opt-in `overview` message rather than a parallel
RPC. Without it, the legacy read path, response and cursor bytes remain unchanged
and have no KEV dependency. With it, existing top-level scope selects workloads;
scope fields in the nested finding filter are rejected. Finding filters narrow
counts, not rows, unless `affected_only` explicitly requests positive counts.

The overview SQL groups matching occurrences by workload and canonical ID,
chooses the highest known matching severity using existing semantic CASE ranks,
and then aggregates counts per workload. A left join onto the full selection
preserves zero-count workloads and all existing image/coverage fields. Severity
buckets count unique vulnerabilities, not packages; their sum equals the unique
vulnerability count. KEV counts are distinct canonical IDs. Catalog availability,
page and full-selection total use the same read-only repeatable-read transaction;
unavailable KEV fails the overview rather than supplying false zeroes.

SQL performs seek/order/LIMIT after aggregation. Identity ASC is the default;
finding-count ASC/DESC uses full identity ASC for ties. Overview cursors have a
separate operation/version, bind selection/filter/affected-only/effective-order,
and store the identity plus count when needed. They resume without a boundary
lookup, but cannot be mixed with legacy cursors. No snapshot spans page calls.
See the [workload overview example and limitations](../README.md#workload-overview).

The public read contract accepts one team or the whole tenant. A workload name
requires a team and environment. Advisory details include links to the sources;
v0s uses the scanner's severity rather than storing a separate score.
CISA KEV is catalog membership, not exploitability. Until a
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

Until cutover, v13s forwards its suppression changes with `ForwardV13sSuppression`
on the same `SuppressionService`. It is always accepted: only services in the same
namespace can reach v0s, and v13s only calls it while its own forwarding is enabled.
Each call carries v13s's current assessment of one image name, package and vulnerability, already normalized and checked for conflicts by
v13s. v0s resolves the vulnerability IDs against its own catalog and sets the
assessment, keeping v13s's actor and update time, on every workload currently
resolved to that image name across teams and environments. Without an assessment
it deletes the image name's suppression from every workload, including workloads
that no longer run it, so it cannot reappear when they do again. An unknown or
ambiguous vulnerability, or an assessment for an image name no workload runs, is
returned as an outcome and changes nothing. An assessment only replaces one with an earlier
update time, so a delayed or repeated call cannot undo a newer assessment, including
one repaired by hand. Removals leave no marker, so a delayed assessment can still
recreate a suppression removed after it; the final verification of the migration
reports it. It never adds vulnerabilities or
aliases. Workloads that start running the image name later inherit nothing.

Inventory and scan results can be rebuilt; suppressions cannot. They are durable
human assessments owned here and require backup and recovery.

The deployment chart uses the shared `nais-postgresql` subchart to provision a
CNPG database for new installations; `cloudnative-pg` remains a required Fasit
operator feature. Existing databases can remain independently managed with
`postgresqlEnabled=false`. Managed Clusters are retained on Helm uninstall by
default, but that is not independent release ownership or backup protection.
The shared subchart does not configure backups. See [Operations](operations.md)
for database ownership boundaries and rollout requirements.

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
