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

`ListWorkloads` (both modes), `ListFindings`, `ListVulnerabilities`,
`CountFindings` and `GetSummary` accept the same top-level `workloadSelector`. It wraps a list of
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

Use the same `workloadSelector` at the top level of the other requests;
for per-workload counts also send `"overview": {}` to `ListWorkloads`. SQL applies
selection before grouping, counting, sorting, seek and LIMIT. Finding facets and
overview totals cover the full intersected selection, not the current page,
including on an empty continuation page. Workload overview preserves
zero-count and coverage-gap rows. Existing KEV
availability errors still apply, including for empty selections.

Continue with the same scope/filter/order/selector and the returned token.
Reordering or duplicating references is equivalent; changing the identity set,
including adding/removing an unknown reference, returns `InvalidArgument`.
Restart without a token after an actual selection change. Omitting the selector
preserves existing cursor bytes for unchanged orders (see severity-ASC compatibility
below). Plain `ListWorkloads`
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
Severity DESC is CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN; ASC is UNKNOWN, LOW,
MEDIUM, HIGH, CRITICAL. Previously ASC was LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN.
The single semantic rank is UNKNOWN=0, LOW=1,
MEDIUM=2, HIGH=3, CRITICAL=4; ASC and DESC reverse the severity field exactly.
UNKNOWN is first in ASC and last in DESC. Severity ties use vulnerability
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

On a nonempty page, an empty `nextPageToken` means there is no next page.
For empty-page existence use `page_info` as documented below. Each entry in `cursors`
can also be used to continue after or before its corresponding finding, even if that
finding has since been deleted. Cursors are opaque and versioned, bound to the
normalized filter and ordering, but not page size. Equivalent list permutations,
duplicates, package-type case, purl spellings and omitted/default filter values
are normalized. Replacing an alias with its canonical vulnerability ID is still
a filter change. Changed filters/orders and legacy or incompatible cursors return
`InvalidArgument`; restart without a token. When `orderBy` is present, both field
and direction must be valid and specified.

Old severity-ASC cursors are rejected because UNKNOWN moved from last to first;
restart without a token. Other existing v1 finding orders/cursor bytes remain
compatible, including severity DESC. New severity-ASC cursors use version 2.

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
above, with UNKNOWN first in ASC and last in DESC. Severity/count ties use canonical ID ASC.
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
Finding listing remains a separate operation with the same pagination semantics.

### Bidirectional pagination and PageInfo

`ListFindings`, `ListVulnerabilities` and `ListSuppressions` share
`page_size`, `page_token` and `page_direction`. These are backend keyset
parameters, not offset pagination. Size defaults to 100 for non-positive values
and is capped at 1000. `page_direction` is separate from `order_by.direction`:

| Request | Selection |
|---|---|
| Direction omitted/UNSPECIFIED/FORWARD, no token | First page |
| FORWARD, row token | Nearest rows exclusively **after** the boundary |
| BACKWARD, no token | Last page |
| BACKWARD, same row token | Nearest rows exclusively **before** the boundary |

Unknown direction enum values are `InvalidArgument`. SQL reverses every search
ordering term, including tie-breakers, for BACKWARD, fetches at most size+1 rows,
and returns the bounded page in the original presentation order. Do not invert
`order_by.direction` or reverse returned rows to request a previous page.

Every response from a supporting server contains `page_info`. For a nonempty
page, `has_previous_page` means at least one matching row exists before its first
row, and `has_next_page` means at least one exists after its last row, in the
full filtered selection. These meanings do not depend on traversal direction.
Start/end cursors are already available as the first/last entries in `cursors`;
there are no redundant start/end response fields.

`next_page_token` retains its forward meaning: the last returned row's cursor
when `has_next_page` is true, otherwise empty. To continue BACKWARD, use the
first returned cursor with BACKWARD when `has_previous_page` is true.

Empty pages have no row cursors or `next_page_token`; GraphQL start/end cursors
are null, never the submitted boundary. Their flags describe the boundary:

- Empty FORWARD/after: next=false; previous is true if any matching row exists
  **on or before** the supplied boundary.
- Empty BACKWARD/before: previous=false; next is true if any matching row exists
  **on or after** the supplied boundary.
- Empty selection without a boundary: both false.
- A deleted boundary contributes no row, but its stored ordering values still
  define the seek. If the whole selection disappears, both flags are false.

Pages, boundary-existence checks and existing totals/facets share one read-only
repeatable-read snapshot per request. Separate requests remain live, not a
snapshot: rows can disappear or change sort values and full-selection totals
can change. An existence flag does not guarantee a nonempty later request.
Pagination never narrows `package_type_counts`, `total_count`, or the counts
inside vulnerability summaries.

Cursor bindings include the effective scope, workloadSelector when supported,
normalized filter and presentation order, but exclude size and traversal.
Changing direction with the same row cursor is valid; changing the selection
or order is `InvalidArgument`. Normalized set permutations/duplicates remain
equivalent; substituting an alias with its canonical ID remains a filter change.

Compatibility:

- Findings and vulnerability overview retain existing v1 cursors for unchanged
  orders. Severity ASC requires restart; new cursors for that order are v2.
- Suppressions now have versioned, operation/scope/filter/order-bound cursors.
  Old unbound suppression cursors cannot prove their selection and are rejected
  with a restart instruction. The fixed presentation remains team, environment,
  workload, image name, package key, vulnerability ID, all ASC.
- Cursors from different operations are not interchangeable. Boundary-row
  deletion does not invalidate an otherwise compatible cursor.
- Existing forward clients can omit `page_direction` and ignore `page_info`.
  Their per-row and next-token continuation remains unchanged, except the
  documented severity-ASC order and required cursor restarts.

For example, to return to the preceding finding page, keep the same filter,
selector and order, and use the first cursor from the current page:

```sh
grpcurl -plaintext -d '{
  "filter": {"team": "my-team"},
  "orderBy": {"field": "FIELD_SEVERITY", "direction": "DIRECTION_DESC"},
  "pageSize": 2,
  "pageToken": "<first cursor from the current page>",
  "pageDirection": "PAGE_DIRECTION_BACKWARD"
}' localhost:50051 v0s.v1.VulnerabilityService/ListFindings
```

#### nais/api integration example

nais/api currently wraps the v0s token in its selection-bound `pageCursor`.
Continue decoding/validating that wrapper; only its `Token` drives the backend
seek. The wrapper's `Offset` is display bookkeeping, not a database offset or
a guaranteed rank across live requests.

The following adaptation belongs in nais/api's v0s adapter, **not** its
offset-based `pagination.ParsePage`. It illustrates `ListVulnerabilities`,
whose current adapter keeps every returned row. `backendToken` is the decoded
`pageCursor.Token` from after/before (empty if no boundary), and `size` has passed
the API's existing positive-size/max-200 validation. Reject conflicting
first/last, first/before, last/after, or simultaneous after/before.

```go
request := &protoapi.ListVulnerabilitiesRequest{
    Filter: filter, WorkloadSelector: selector, OrderBy: order,
}
data, err := proto.Marshal(request)
if err != nil {
    return nil, fmt.Errorf("encode vulnerability selection: %w", err)
}
selection := selectionKey("vulnerability-overview", workloadBinding+string(data))

request.PageSize = int32(size)
request.PageToken = backendToken
request.PageDirection = protoapi.PageDirection_PAGE_DIRECTION_FORWARD
if last != nil || before != nil {
    request.PageDirection = protoapi.PageDirection_PAGE_DIRECTION_BACKWARD
}
resp, err := client.ListVulnerabilities(ctx, request)
if err != nil {
    return nil, backendError("list v0s vulnerability overview", err)
}
if resp.GetPageInfo() == nil || len(resp.GetCursors()) != len(resp.GetVulnerabilities()) {
    return nil, fmt.Errorf("v0s bidirectional pagination is not available")
}
```

Compute/validate `selection` **before** adding pagination parameters: direction,
size and token must not enter the API wrapper's selection fingerprint. Thus
`first=n, after=edge` maps to FORWARD/size=n/token=edge.Token;
`last=n, before=edge` maps to BACKWARD/size=n/token=the same edge.Token.
BACKWARD without a token also supports last-page retrieval if nais/api chooses
to expose it; global display positions cannot be inferred from keyset alone.

Build edges in response order, retaining the existing GraphQL wrapper format.
Here `displayStart` is the adapter's display bookkeeping (for before, boundary
display offset minus the actual returned row count; not an absolute live rank):

```go
edges := make([]pagination.Edge[*protoapi.VulnerabilitySummary], 0, len(resp.GetVulnerabilities()))
for i, row := range resp.GetVulnerabilities() {
    token := resp.GetCursors()[i]
    if token == "" {
        return nil, fmt.Errorf("v0s returned an empty row cursor")
    }
    position := displayStart + i
    data, err := json.Marshal(pageCursor{
        Version: 1, Selection: selection, Token: token, Offset: position,
    })
    if err != nil {
        return nil, fmt.Errorf("encode vulnerability cursor: %w", err)
    }
    edges = append(edges, pagination.Edge[*protoapi.VulnerabilitySummary]{
        Node: row,
        Cursor: pagination.Cursor{
            Keyset: base64.RawURLEncoding.EncodeToString(data), Offset: position,
        },
    })
}
info := pagination.PageInfo{
    HasNextPage: resp.GetPageInfo().GetHasNextPage(),
    HasPreviousPage: resp.GetPageInfo().GetHasPreviousPage(),
    TotalCount: int(resp.GetTotalCount()),
}
if len(edges) > 0 {
    info.StartCursor = &edges[0].Cursor
    info.EndCursor = &edges[len(edges)-1].Cursor
}
```

No extra API-side size+1 request is needed for this unfiltered mapping: v0s
already probes continuation. Preserve existing count loaders/full-selection
facets for the other connections. Use the same request mapping for findings
and suppressions, with their existing scope/filter fields.

**Inventory post-filtering matters.** Today's nais/api `readPage` can discard
findings with obsolete images and suppressions absent from inventory. Backend
flags describe the backend selection, not this stricter API selection. A direct
copy is correct only when every row is retained. When retaining the keep-predicate,
the future adapter must refill bounded pages in the requested direction:
end cursor/FORWARD for after, first cursor/BACKWARD for before. Prepend preceding
chunks without reversing their presentation order. For exact PageInfo, probe
both outside edges with the same predicate until a retained row is found or the
backend boundary is exhausted; empty pages use the original request boundary.
Such directional keyset checks are not fetching previous pages to simulate
backward pagination. Never derive existence from the presence of after/before
or a stored display offset. Inventory churn still follows live-data semantics.
This adapter work and its tests belong in a separate nais/api change.

Adoption requires a new generated client release. Follow the existing
`api/v*` automatic minor-release policy after approved main integration; do not
manually publish or merge to main without explicit permission. Then update
nais/api's `github.com/nais/v0s/api` dependency to that published module version.

### Workload overview

Use `ListWorkloads` with `overview: {}` to add server-computed finding counts
to a batch of selected workloads. Nais API owns its workload lists, filters,
sorting and UI pagination; it uses overview to enrich the workloads it has
already selected. Without `overview`, neither counts nor `totalCount` are
returned and no KEV catalog is required.

Workload **selection** uses the existing top-level `team`, `environment` and
`workload` fields, intersected with `workloadSelector` when present.
`overview.findingFilter` reuses `FindingFilter` for matching
findings, including severity, KEV, fix availability, assessments and package
type. Its `team`, `environment` and `workload` must be empty; competing scope
fields are rejected with `InvalidArgument`, even if they repeat the selection.
Suppressed findings are excluded by default.

All selected workloads remain present, including scanned workloads
with no findings, pending/failed scans, missing SBOMs and unresolved images.
Finding filters affect counts, not selection. An omitted selector adds no
restriction; an explicitly empty selector returns no workloads.

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
  "workloadSelector": {"workloads": [
    {"environment": "prod", "team": "my-team", "name": "app"},
    {"environment": "prod", "team": "my-team", "name": "worker"}
  ]},
  "overview": {"findingFilter": {"packageType": "npm"}},
  "pageSize": 1000
}' localhost:50051 v0s.v1.VulnerabilityService/ListWorkloads
```

Rows are ordered by environment, team and workload name. The default page size
is 100; the maximum is 1000. To fetch the full batch, keep the same scope,
selector and finding filter and pass `nextPageToken` as `pageToken` until the
response has no next token. Tokens resume even if the boundary workload was
deleted. Invalid tokens, including tokens from the previous overview format
or from plain `ListWorkloads`, return `InvalidArgument`; restart without a token.
Requests do not share a snapshot across pages.

`totalCount` is the size of the full workload selection before pagination,
including on an empty page. It is not used for UI pagination, but nais/api
currently checks that it is present to detect overview support. Keep the field
until all relevant nais/api consumers accept responses without it, including
empty responses, while still surfacing unavailable backend data and missing
counts on returned rows.

### Summary of findings and coverage

`GetSummary` is one non-paginated operation for both tenant-wide and team-scoped
summaries. Existing operations and cursors are unchanged. Top-level `team`,
`environment`, `workload` and `workloadSelector` select workloads, as in the
workload overview. A `workload` still requires team and environment.
`findingFilter` narrows findings only; its team/environment/workload fields must
be empty, even when they repeat the top-level scope (`InvalidArgument`).
Suppressed findings are excluded by default.

Team example:

```sh
grpcurl -plaintext -d '{
  "team": "my-team",
  "findingFilter": {"packageType": "npm"}
}' localhost:50051 v0s.v1.VulnerabilityService/GetSummary
```

Global, externally computed workload selection across teams and environments:

```sh
grpcurl -plaintext -d '{
  "workloadSelector": {
    "workloads": [
      {"environment": "dev", "team": "team-a", "name": "app"},
      {"environment": "prod", "team": "team-b", "name": "worker"}
    ]
  }
}' localhost:50051 v0s.v1.VulnerabilityService/GetSummary
```

Send `{}` for the whole tenant. Omitted selector means no extra restriction;
`"workloadSelector": {}` means none. Scope and selector intersect. Unknown/deleted
identities do not match; duplicates/order do not change counts. The existing
4 MiB protobuf request limit applies, with no separate selector count cap.

The response separates matching-finding facts from workload coverage:

- `findingCount` counts workload/package occurrences after all finding filters.
  Workloads sharing an image contribute separately.
- `uniqueVulnerabilityCount` counts distinct canonical IDs across the entire
  filtered selection, **not** the sum of workload-level unique counts. Alias
  filters cannot multiply findings or vulnerabilities.
- `affectedWorkloadCount` counts distinct full workload identities with at least
  one matching finding.
- `severityCounts` counts each unique canonical vulnerability once at its
  highest known severity across matching findings in the entire selection.
  Filtering happens first. UNKNOWN applies only when all matching findings for
  that vulnerability are UNKNOWN. The five buckets sum to the unique count.
  No severity is calculated from CVSS.
- `uniqueKevVulnerabilityCount` and `kevAffectedWorkloadCount` count distinct
  canonical IDs and workloads with matching KEV findings, respectively, in
  **the same filtered finding selection**.

`coverage.totalWorkloadCount` is all selected workloads, including those without
findings or resolved images. Finding filters, including KEV and assessments, do
not change this denominator or the coverage categories. Each workload contributes
to exactly one of `scannedCount`, `pendingCount`, `noSbomCount`, `failedCount` and
`unresolvedImageCount`; their sum equals the total. These count workloads, not
unique images. Status follows existing image semantics: missing/failed SBOMs
remain NO_SBOM/FAILED; a fetched image with a successful scan remains SCANNED
despite a later rescan error. A fetched image not yet successfully scanned is
PENDING without an error, FAILED with an error. An unresolved image is a separate
category. Zero findings or SCANNED is not a guarantee of cleanliness or completeness.
Only counts are returned; clients may calculate percentages.

With an available KEV catalog, an empty workload selection returns zero for every
count. As in workload overview reads, an unavailable KEV catalog returns
`Unavailable` for the whole request, including an empty selection, never
success-shaped KEV zeroes. The catalog check and all aggregates share one
read-only repeatable-read database snapshot. SQL computes global distinct counts,
severity and coverage in one aggregate query after the catalog check, not by
summing per-workload totals or paging through listings. Later requests use live
data, not the same snapshot. No label, user or RBAC logic is introduced.

## Documentation

[Documentation index](docs/README.md) ·
[Developer contract proposal](docs/utviklerkontrakt.md) ·
[API, CLI and Console proposal](docs/api-cli-console-forslag.html)

[Domain language](CONTEXT.md) · [Architecture](docs/architecture.md) ·
[Operations](docs/operations.md) · [Verification](docs/verification.md) ·
[Helm chart](charts/README.md)

The developer contract and client proposal are design material, not implemented
client features or evidence of a completed cutover.
