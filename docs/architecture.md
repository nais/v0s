# Architecture

v0s is a per-tenant inventory and vulnerability service. It reports source facts
and teams' assessments; it does not decide which findings to prioritize.
See [CONTEXT.md](../CONTEXT.md) for identities and counting semantics, and the
[protobuf contract](../proto/v0s/v1/v0s.proto) for the API.

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

Domain types live in the root Go package. `internal/database` owns hand-written
SQL and embedded, numbered migrations applied under an advisory lock. Postgres
holds shared application state; each replica's Trivy DB is a replaceable local
cache.

Findings are listed and counted per workload. Severity and fix information come
from the advisory source; EPSS and KEV come from FIRST and CISA without our own
thresholds or scoring. Components are searchable even when they have no findings.
No finding history, trends or first-seen timestamps are kept.

Suppressions are keyed by team, image name, versionless package key and canonical
vulnerability ID. They survive package versions and image builds, and affect only
the team's own workloads. Setting replaces the current assessment; deleting
removes it. There is no expiry or assessment history in v0s.

Inventory and scan results can be rebuilt; suppressions cannot. They are durable
human assessments owned here and require backup and recovery.

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
