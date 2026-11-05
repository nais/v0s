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
- sync: every minute, the workloads from Nais API replace `workloads`, per environment. A
  workload listed twice with different images fails that environment's sync, which keeps
  the previous snapshot rather than picking one image

A crash loses nothing. On restart, the loops see the same desired state.

## Workloads from Nais API, not from the clusters

Nais API already watches every cluster of the tenant, including on-prem ones,
and knows every application and job with its effective image. v0s reads them with
one call per sync to `Workloads.ListImages` on Nais API's internal gRPC API, which
is unauthenticated and reached through NetworkPolicy, like its other internal
clients. It needs no access to the clusters: no RBAC, no cluster credentials, and
no watch streams through the API server proxies.

`Workloads.ListImages` is not yet in nais/api upstream: it is proposed in nais/api#609,
the dev-nais pilot runs a local build of nais-api with it, and `third_party/naisapi` is a
copy of its proto. The GraphQL API would have done without changing nais-api, but needs a
service account token, and creating one needs a team or admin role.

This replaced watching Pods across clusters. The Pod watches cost cluster access
and RBAC per cluster, and broke every 60 seconds on the HAProxy in front of the
API servers. Reporting the deployed image instead of the running one is what
teams can act on: a workload scaled to zero still has its image.

Only teams' workloads are in scope. Nais API leaves out `nais-system`, and v0s
follows it: the platform's own workloads get their own tooling rather than
sharing a team-facing service.

About three quarters of nav's workloads carry a digest from deploy. For the rest
v0s resolves the tag with a registry `HEAD` and reuses the digest for an hour,
or longer while the registry fails. A workload whose tag has never been resolved
is left out until it is. Nais API lists only environments whose caches are
synced, and v0s skips a sync on any error, so a partial answer is never taken
for an empty tenant.

## Suppressions are owned here, per team, keyed on package key

The key is `(team, image name, package key, vulnerability ID)`. It is
version-agnostic, so an assessment survives a version bump of the package, and
tag-agnostic, so it survives new image builds. It is per team because an image
name can be shared by several teams, and one team's assessment must not change
what another team sees. The caller then only has to authorize the actor for one
team, which is how Nais API authorizes everything else.

The cost is that whether a finding is suppressed depends on whose view it is:
per workload it is the workload team's decision, and once per finding it takes
every team using the image within the request. For one team, the usual request,
the two agree.

Rows are append-only. Changing an assessment means revoking the old row and
inserting a new one. A partial unique index allows at most one unrevoked row per
key. Expiry is evaluated at read time, and creating a suppression revokes an
expired predecessor in the same transaction.

## Facts only

There is no priority, risk score or top list. EPSS and KEV are fields on the
finding. Counts are plain `GROUP BY` facets.

## Everyone in the tenant can read everything

Any user may see any team's findings, so a CVE can be traced to every team that
has it. v0s has no per-user read access: its callers are trusted services, and
team filters narrow a query, they do not restrict it. Only writes are scoped:
a caller must authorize the actor for the team a suppression belongs to.

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
