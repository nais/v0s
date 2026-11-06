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

Each loop reads the desired state from Postgres, does the work, and writes the
result back. There is no River and no separate queue. Each loop that writes runs
behind a cluster-wide advisory lock, so with several replicas one does the work
and the others only serve the API. Scans take milliseconds, so one worker keeps
up, and without parallel workers there are no leases to expire and no scan
running twice:

- fetch: images whose SBOM is not yet fetched, or due for a retry
- scan: images in use whose `scanned_db_version` differs from the loaded DB, unless a scan with that DB already failed
- enrich: EPSS and KEV once a day
- vulndb: check the registry for a newer DB every hour, on every replica, since each holds its own copy
- sync: every minute, the workloads from Nais API replace `workloads`, per environment, and the
  images no workload uses any more are deleted with their SBOMs and findings. A workload
  listed twice with different images fails that environment's sync, which keeps the
  previous snapshot rather than picking one image

A crash loses nothing. On restart, the loops see the same desired state. A scan
that kills the process is retried, and given up for that DB version after three
attempts.

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
v0s resolves the tag with a registry `HEAD` once, and keeps the digest while the
tag is in use. A workload whose image cannot be resolved (or parsed) is stored
without an image and with the reason, and the lookup is retried on the next sync.
Nais API lists only environments whose caches are synced, and v0s skips a sync
on any error, so a partial answer is never taken for an empty tenant.

Tags moved in the registry are not handled. Pushing a new image to an existing
tag (`latest`, say) does not change the workload in Nais API, and v0s keeps the
digest it resolved first, until it restarts. The cache is per process, so with
more than one replica a moved tag can make the workload's digest alternate
between replicas. Teams that want current results deploy a new tag or a digest.

## Suppressions are owned here, per team, keyed on package key

The key is `(team, image name, package key, vulnerability ID)`. It is
version-agnostic, so an assessment survives a version bump of the package, and
tag-agnostic, so it survives new image builds. It is per team because an image
name can be shared by several teams, and one team's assessment must not change
what another team sees. The caller then only has to authorize the actor for one
team, which is how Nais API authorizes everything else.

A finding belongs to one workload, so whether it is suppressed is that
workload's team's decision, with no special case for images shared by teams.

Only the current assessment is kept: setting one replaces the previous one, and
deleting it removes it. Nais API already logs who changed what, so v0s keeps no
history of its own. An assessment has a state and a reason in the team's words;
the VEX justification vocabulary is left out until something consumes it.
There is no expiry: v13s has none and no one has asked for it, and without it
whether a finding is suppressed does not depend on the time it is read.

## Facts only

Nais does not judge severity or priority, neither here nor downstream. There is
no priority tier, risk score or top list. Severity is the advisory source's, with
the source named; EPSS and KEV are fields on the finding. Counts are plain
`GROUP BY` facets.

## Current state, no history

v0s serves the findings as they are now. There are no trend graphs or
time-to-fix metrics to feed, so there are no finding events, summary snapshots
or first-seen times, and images are deleted as soon as no workload uses them.

## Everyone in the tenant can read everything; no authentication

Any user may see any team's findings, so a CVE can be traced to every team that
has it. v0s has no per-user read access: its callers are trusted services, and
team filters narrow a query, they do not restrict it. Only writes are scoped:
a caller must authorize the actor for the team a suppression belongs to.

The API has no authentication, like Nais API's internal gRPC API: NetworkPolicy
lets only `nais-system` reach it. The cost is that anything running there can
set or delete suppressions in any team's name.

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
