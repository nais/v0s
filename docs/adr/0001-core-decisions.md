# 0001 Core decisions

Date: 2026-10-30. Status: accepted.

## Trivy as a Go library, not a subprocess or server

Scanning calls Trivy's OS and language package scanners
(`github.com/aquasecurity/trivy/pkg/scan/ospkg` and `.../langpkg`) and its
vulnerability `FillInfo` in-process against a local trivy-db. We get typed results, no binary to keep in sync with the
image, and no shared Trivy server to isolate per tenant (it has no tenant
isolation). The cost is a large module graph and Trivy's unstable internal API.
Only `internal/scan` imports Trivy, so an upgrade touches one package.

trivy-db uses a process-global bolt handle. `internal/scan` owns it, both lifecycle and matching. A DB swap
takes a write lock, and scans hold a read lock.

## Level-triggered loops, no job queue

Each loop reads the desired state from Postgres, claims work with
`FOR UPDATE SKIP LOCKED`, and writes the result back. There is no River and no
separate queue:

- fetch: images whose SBOM is not yet fetched, or due for a retry
- scan: images in use whose `scanned_db_version` differs from the loaded DB, unless a scan with that DB already failed
- enrich: EPSS and KEV once a day, behind an advisory lock
- vulndb: check the registry for a newer DB every hour
- sync: every minute, the workloads from Nais API replace `workload_images`

A crash loses nothing. On restart, the loops see the same desired state.

## Workloads from Nais API, not from the clusters

Nais API already watches every cluster of the tenant, including on-prem ones,
and serves applications and jobs with their effective image. v0s reads them with
one GraphQL query per sync, authenticated with a Nais API service account token.
It needs no access to the clusters: no RBAC, no cluster credentials, and no
watch streams through the API server proxies.

This replaced watching Pods across clusters. The Pod watches cost cluster access
and RBAC per cluster, and broke every 60 seconds on the HAProxy in front of the
API servers. Reporting the deployed image instead of the running one is what
teams can act on: a workload scaled to zero still has its image.

About three quarters of nav's workloads carry a digest from deploy. For the rest
v0s resolves the tag with a registry `HEAD` and reuses the digest for an hour,
or longer while the registry fails. A workload whose tag has never been resolved
is left out until it is. Nais API serves only once its caches are synced, and
v0s skips a sync on any error, so a partial answer is never taken for an empty
tenant.

## Suppressions are owned here, keyed on package key

The key is `(image name, package key, vulnerability ID)`. It is
version-agnostic, so an assessment survives a version bump of the package, and
tag-agnostic, so it survives new image builds. Team-wide scope is deferred
because an image name can be shared by several teams.

Rows are append-only. Changing an assessment means revoking the old row and
inserting a new one. A partial unique index allows at most one unrevoked row per
key. Expiry is evaluated at read time, and creating a suppression revokes an
expired predecessor in the same transaction.

## Facts only

There is no priority, risk score or top list. EPSS and KEV are fields on the
finding. Counts are plain `GROUP BY` facets.

## Postgres-backed integration tests without Docker

Tests that need Postgres start a throwaway cluster with `initdb`/`pg_ctl` from
PATH, or use `V0S_TEST_DATABASE_URL`. If neither is available, they skip
explicitly.

## pgx with hand-written SQL, no sqlc

The read API has many optional filters, which sqlc handles badly (v13s ends up
with `sqlc.narg` chains). Every package that touches the database owns its SQL
next to the Go code that uses it, in `internal/database`. The schema is a set of
numbered, embedded migrations that a small runner applies under an advisory
lock.

## Domain types in the root package

`github.com/nais/v0s` holds plain domain types (Image, Component, Finding, …)
with no dependencies. `internal/scan` produces them, and `internal/database` and
`internal/grpcapi` consume them. Trivy types never leave `internal/scan`.
