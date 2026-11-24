# v0s

v0s is a vulnerability service for Nais, built around Nais API's workload
inventory. It answers three questions about a tenant's applications and jobs:

- Which known vulnerabilities affect their images, and is a fix available?
- Where is a particular package or version deployed, even if it has no findings?
- Which findings has a team assessed as not affected, false positive or accepted risk?

It reads deployed images from Nais API, verifies their attested CycloneDX SBOMs,
and matches them against Trivy's vulnerability database. Stored SBOMs are rescanned
when the database changes; images are never pulled. Results, coverage gaps and
workload-scoped suppressions are served over gRPC. Clients can discover other
affected workloads and explicitly assess selected workloads in a batch.

Nais API is a required runtime dependency and the sole source of workload
inventory. v0s does not watch Kubernetes directly or offer a standalone mode.
One v0s service per tenant, Postgres for state, no queue or separate scanner
service. The aim is to replace v13s and Dependency-Track for this use case—not
to reproduce all their features.

## Boundaries

- Facts, not prioritization: severity, fix information, EPSS and KEV, but no risk
  score, priority tiers, policy engine, trends or history.
- Team workloads only; no platform sidecars or workloads in `nais-system`.
- Mutable tags are resolved once; moving a tag is not tracked. Deploy a new tag
  or digest to change the image.
- Reads are tenant-wide. Trusted callers authorize suppression writes;
  NetworkPolicy is the API's trust boundary, not application authentication.

## Development

```sh
mise install
mise run check
```

Database tests need PostgreSQL's `initdb` and `pg_ctl` on `PATH` or in `V0S_PG_BIN`,
or an existing server via `V0S_TEST_DATABASE_URL`. Without either, they skip.
The authoritative v0s [protobuf](proto/v0s/v1/v0s.proto) and generated Go
bindings live in this repository. The client is a separate Go module under
[`api/`](api/go.mod); the server uses it through a local `replace`.
Run `mise run generate` after changing either the public contract or the
vendored Nais API proto. `mise run check` tests and checks both Go modules
explicitly; `go test ./...` from the root does not cover `api/`.
`mise run build` builds both modules and writes
`bin/v0s`; `mise run build:image` builds a local Linux image without pushing.
Green builds on `main` publish signed images and Helm charts to GAR, then assign
the chart through Fasit to `ci-nais` management with a wait for success before
assigning all management environments.

## Go client

Import `github.com/nais/v0s/api/v0s/v1`. The client module requires Go 1.26.11,
not the server's Go version or its Trivy dependencies.

Client releases use `api/v*` tags on commits in this repository, independently
of server image/chart releases. After checks pass on `main`, CI publishes a
new tag when `api/` or `proto/v0s/` differs from the last client release.
The first release is `api/v0.3.0`, continuing after `v0.2.0` in the former
`nais/v0s-api` repository. Subsequent releases increment the minor version
(`api/v0.4.0`, `api/v0.5.0`, ...), since v0 contract changes may be breaking.
For example, after publishing `api/v0.3.0`:

```sh
go get github.com/nais/v0s/api@v0.3.0
```

The `api/` prefix belongs to the Git tag, not the version passed to `go get`.
Versions `api/v1.x.y` keep the same module/import paths; a future v2 needs a
major-versioned module path. Automatic version selection currently supports
only v0; moving to v1 requires updating the release policy.

To adopt this client later, nais/api must add the published module dependency,
switch its client imports to `github.com/nais/v0s/api/v0s/v1`, and remove any
previous generated v0s client and its generation source. Call sites must stop
expecting CVSS and use the advisory references instead. The gRPC service/RPC
names are unchanged. No nais/api changes are part of this change.

Finding filters use only `vulnerability_ids`, including for a single ID or
alias. An empty list does not filter by vulnerability.

### Explicit workload selection

`ListWorkloads` (both modes), `ListFindings`, `ListVulnerabilities` and
`CountFindings` accept the same top-level `workloadSelector`. It wraps a list of
existing `WorkloadRef` identities: `environment`, `team`, `name`. It is not part
of `FindingFilter`, so workload overview requests have just one selector.
nais/api can compute the list externally from labels or the user's teams; v0s
does not interpret labels, users or permissions.

- Omitted `workloadSelector`: no additional restriction, preserving existing
  behavior.
- `"workloadSelector": {}` or `{"workloads": []}`: match **no workloads**, never
  all workloads.
- All three identity fields must be nonblank; invalid entries are
  `InvalidArgument`. Identities are matched exactly. Ordering and duplicate
  identities are normalized without changing the caller's input.
- The selector **intersects** existing team/environment/workload scope and
  finding filters. It never overrides them. Existing requirements for a fully
  scoped `workload` filter still apply.
- Unknown/deleted workloads match nothing. Workloads sharing an image remain
  separate; selecting one does not select the others.

For example, after computing a selection outside v0s:

```sh
grpcurl -plaintext -d '{
  "workloadSelector": {
    "workloads": [
      {"environment": "dev", "team": "team-a", "name": "app"},
      {"environment": "prod", "team": "team-b", "name": "worker"}
    ]
  },
  "filter": {"packageType": "npm"},
  "orderBy": {"field": "FIELD_SEVERITY", "direction": "DIRECTION_DESC"},
  "pageSize": 2
}' localhost:50051 v0s.v1.VulnerabilityService/ListFindings
```

Use the same `workloadSelector` at the top level of the other three requests;
for workload counts also send `"overview": {}` to `ListWorkloads`. SQL applies
selection before grouping, counting, sorting, seek and LIMIT. Finding facets and
overview totals cover the full intersected selection, not the current page,
including on an empty continuation page. Workload overview still preserves
zero-count/coverage-gap rows unless `affectedOnly` is true. Existing KEV
availability errors still apply, including for empty selections.

Continue with the same scope/filter/order/selector and the returned token.
Reordering or duplicating references is equivalent; changing the identity set,
including adding/removing an unknown reference, returns `InvalidArgument`.
Restart without a token after an actual selection change. No selector means
existing cursor bytes and compatibility are preserved. Plain `ListWorkloads`
with a selector uses a separate versioned, scope/selection-bound cursor; it
cannot be mixed with unselected legacy cursors or overview cursors. Deleting a
boundary workload does not invalidate continuation with the same selector.
Pagination remains live, not a snapshot across requests.

There is **no separate entry-count limit**. Selection uses three parameterized
SQL arrays, not one query or three bind parameters per workload, so it avoids
PostgreSQL's bind-parameter limit for large tenant selections. The existing
**4 MiB encoded protobuf request limit** applies to the whole request; oversized
messages fail with `ResourceExhausted`. Lists are never truncated and there is no
fallback to all workloads. Tests exercise 25,000 unknown identities plus matching
workloads after them, as well as transport-level rejection over 4 MiB.

### Finding ordering and pagination

Without `order_by`, `ListFindings` retains its existing order: environment,
team, workload name, vulnerability ID and purl, all ascending. Explicit ordering
supports severity or vulnerability ID in either direction, in SQL before LIMIT.
Severity DESC is CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN; ASC is LOW, MEDIUM,
HIGH, CRITICAL, UNKNOWN. UNKNOWN is always last. Severity ties use vulnerability
ID ascending. Remaining ties, including for ID ordering, use environment, team,
workload name and purl ascending.

For example, against a local plaintext endpoint with reflection:

```sh
grpcurl -plaintext -d '{
  "filter": {"team": "my-team"},
  "orderBy": {"field": "FIELD_SEVERITY", "direction": "DIRECTION_DESC"},
  "pageSize": 2
}' localhost:50051 v0s.v1.VulnerabilityService/ListFindings
```

For the next page, repeat the filter and order and copy `nextPageToken` from
the response into `pageToken`:

```sh
grpcurl -plaintext -d '{
  "filter": {"team": "my-team"},
  "orderBy": {"field": "FIELD_SEVERITY", "direction": "DIRECTION_DESC"},
  "pageSize": 2,
  "pageToken": "<nextPageToken from the previous response>"
}' localhost:50051 v0s.v1.VulnerabilityService/ListFindings
```

An empty `nextPageToken` means there is no next page. Each entry in `cursors`
can also be used to continue after its corresponding finding, even if that
finding has since been deleted. Cursors are opaque and versioned, bound to the
normalized filter and ordering, but not page size. Equivalent list permutations,
duplicates, package-type case, purl spellings and omitted/default filter values
are normalized. Replacing an alias with its canonical vulnerability ID is still
a filter change. Changed filters/orders and legacy or incompatible cursors return
`InvalidArgument`; restart without a token. When `orderBy` is present, both field
and direction must be valid and specified.

Each request reads live data; there is no snapshot across requests. Changes to
sort values can move findings between pages. Package-type facets always cover
the entire filtered selection, unaffected by ordering, cursor or page size.

### Vulnerability overview

`ListVulnerabilities` returns one `VulnerabilitySummary` per canonical
`vulnerabilityId` in current workload findings, without copying advisory data.
Use `GetVulnerability` for details.

The request reuses `FindingFilter`: filters apply **before** grouping, including
severity, package type, available fix, KEV and suppression/assessment state
(suppressed findings are excluded by default). Overlapping IDs and aliases do
not multiply rows or counts.

Each summary contains:

- `severity`: highest known severity among matching findings; UNKNOWN only when
  all matching findings are UNKNOWN. No CVSS calculation.
- `findingCount`: all matching workload/package occurrences. Multiple workloads
  sharing an image each contribute their findings.
- `affectedWorkloadCount`: distinct `(environment, team, workload name)` tuples,
  regardless of how many packages are affected in a workload.

Sorting, grouping, counts and pagination happen in SQL. `VulnerabilityOrderBy`
supports `FIELD_SEVERITY`, `FIELD_VULNERABILITY_ID` and
`FIELD_AFFECTED_WORKLOAD_COUNT`, each with `DIRECTION_ASC` or `DIRECTION_DESC`.
Omitting `orderBy` defaults to severity DESC. Severity orders are the same as
above, with UNKNOWN always last. Severity/count ties use canonical ID ASC.
All identifier ordering and seek comparisons use PostgreSQL `COLLATE "C"`:
bytewise, case-sensitive lexical order, **not** natural/numeric CVE order
(`CVE-10` sorts before `CVE-2` in ASC).

```sh
grpcurl -plaintext -d '{
  "filter": {"team": "my-team", "packageType": "npm"},
  "orderBy": {"field": "FIELD_SEVERITY", "direction": "DIRECTION_DESC"},
  "pageSize": 2
}' localhost:50051 v0s.v1.VulnerabilityService/ListVulnerabilities
```

The response contains `vulnerabilities`, `nextPageToken`, one entry in `cursors`
per row, and `totalCount` for all unique canonical IDs in the filtered selection.
The total is independent of cursor, order and page size, including an empty page
after the last result; a selection with no matches has total zero. Each page and
its total use the same database snapshot.

To continue, repeat the filter and order and add
`"pageToken": "<nextPageToken from the response>"`. Stop when `nextPageToken`
is empty. Any per-row cursor also resumes after its row, even if that row has
disappeared. Page size defaults to 100 and is capped at 1000.

Overview cursors have their own operation/version and bind the normalized filter
and effective order, not page size. Omitted order and explicit severity DESC are
equivalent. The filter normalization and alias-substitution rules above apply.
Malformed/incompatible cursors or changed filters/orders return `InvalidArgument`;
restart without a token. Finding cursors and overview cursors are not interchangeable.
Requests use live data, not a snapshot between calls: updates to severity or
workload counts can move rows, and totals can change. A loaded KEV catalog is
required only when filtering on KEV; otherwise this overview has no KEV dependency.
Existing `ListFindings` behavior is unchanged.

### Workload overview

`ListWorkloads` is extended additively: send `overview: {}` to opt in to
per-workload finding counts, per-row cursors and `totalCount`. Without `overview`,
the existing response and identity ordering are unchanged; counts/total are
absent and no KEV catalog is required. The legacy cursor format is unchanged
when `workloadSelector` is also omitted. There is no separate workload overview RPC.

Workload **selection** uses the existing top-level `team`, `environment` and
`workload` fields, intersected with `workloadSelector` when present.
`overview.findingFilter` reuses `FindingFilter` for matching
findings, including severity, KEV, fix availability, assessments and package
type. Its `team`, `environment` and `workload` must be empty; competing scope
fields are rejected with `InvalidArgument`, even if they repeat the selection.
Suppressed findings are excluded by default.

All selected workloads remain present by default, including scanned workloads
with no findings, pending/failed scans, missing SBOMs and unresolved images.
Finding filters affect counts, not selection. Set `overview.affectedOnly: true`
to keep only workloads with at least one matching finding.

Each existing workload row keeps its identity, image reference, image status
and errors, and adds `findingCounts`:

- `findingCount`: matching workload/package occurrences.
- `uniqueVulnerabilityCount`: distinct canonical vulnerability IDs. Aliases do
  not multiply counts, and workloads sharing an image remain separate rows.
- `severityCounts`: unique vulnerabilities by highest known severity across
  their matching packages **within that workload**. UNKNOWN is used only when
  all matching findings are UNKNOWN. The five buckets sum to
  `uniqueVulnerabilityCount`; there is no CVSS-derived severity.
- `uniqueKevVulnerabilityCount`: distinct matching canonical IDs in CISA KEV.
  Overview mode always requires a loaded KEV catalog and fails with `Unavailable`
  if it is missing, rather than returning misleading zero counts.

Zero counts do not prove a successful scan or a complete/clean image: always
inspect image status, image errors and `resolveError`.

```sh
grpcurl -plaintext -d '{
  "team": "my-team",
  "overview": {
    "findingFilter": {"packageType": "npm"},
    "affectedOnly": false,
    "orderBy": {"field": "FIELD_FINDING_COUNT", "direction": "DIRECTION_DESC"}
  },
  "pageSize": 2
}' localhost:50051 v0s.v1.VulnerabilityService/ListWorkloads
```

Default ordering is environment, team, workload ASC, matching legacy mode.
Explicit `FIELD_WORKLOAD` accepts only `DIRECTION_ASC`; `FIELD_FINDING_COUNT`
accepts ASC and DESC with the full identity ASC as tie-breaker. SQL performs
filtering, aggregation, sorting, seek and LIMIT. `totalCount` covers the selection
after `affectedOnly` but before the cursor/LIMIT, including on an empty final page.

Continue with the same selection and overview options plus
`"pageToken": "<nextPageToken from the response>"`. Stop at an empty next token.
Each `cursors` entry also continues after its row, even if the boundary workload
has been deleted. Overview cursors are versioned and bound to normalized
selection, finding filter, `affectedOnly` and effective order, not page size.
Omitted ordering equals explicit workload ASC. Legacy and overview cursors are
not interchangeable; invalid/incompatible cursors or changed parameters return
`InvalidArgument` and require restarting without a token.

Page and total share a database snapshot within the request, but requests are
not a snapshot across pages. Changing finding counts can move rows; totals may
change. Existing scope supports one team or the whole tenant, optional
environment, or one fully scoped workload. The shared
[explicit workload selector](#explicit-workload-selection) additionally supports
externally computed multi-team/multi-environment subsets without label/RBAC logic.

## Documentation

[Documentation index](docs/README.md) ·
[Developer contract proposal](docs/utviklerkontrakt.md) ·
[API, CLI and Console proposal](docs/api-cli-console-forslag.html)

[Domain language](CONTEXT.md) · [Architecture](docs/architecture.md) ·
[Operations](docs/operations.md) · [Verification](docs/verification.md) ·
[Helm chart](charts/README.md)

The developer contract and client proposal are design material, not implemented
client features or evidence of a completed cutover.
