# 0001 Core decisions

Date: 2026-10-30. Status: accepted.

## Trivy as a Go library, not a subprocess or server

Scanning calls `github.com/aquasecurity/trivy/pkg/scan/local` in-process against
a local trivy-db. We get typed results, no binary to keep in sync with the
image, and no shared Trivy server to isolate per tenant (it has no tenant
isolation). The cost is a large module graph and Trivy's unstable internal API.
Only `internal/scan` and `internal/vulndb` import Trivy, so an upgrade touches
two packages.

trivy-db uses a process-global bolt handle. `internal/vulndb` owns it. A DB swap
takes a write lock, and scans hold a read lock.

## Level-triggered loops, no job queue

Each loop reads the desired state from Postgres, claims work with
`FOR UPDATE SKIP LOCKED`, and writes the result back. There is no River and no
separate queue:

- fetch: images whose SBOM is not yet fetched, or due for a retry
- scan: images in use whose `scanned_db_version` differs from the loaded DB
- enrich: EPSS and KEV once a day, behind an advisory lock
- vulndb: check the registry for a newer DB every hour
- watch: pod informers keep `workload_images` current

A crash loses nothing. On restart, the loops see the same desired state.

## Pods, not Deployments

What runs is what we report. Pod `status.containerStatuses[].imageID` gives the
digest without resolving tags against a registry. The workload name comes from
the `app` label and the team from the namespace. Pods without an `app` label are
ignored.

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
