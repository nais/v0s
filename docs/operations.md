# Operations

## Building and publishing

Mise owns build, checks and generation; see `mise tasks`. The Dockerfile builds a
static Go binary and runs it as UID/GID 65532 in `scratch`, with only the binary,
CA certificates and writable cache/temp directories. The build image is pinned
by digest. `mise run build:image` builds `v0s:local` for Linux/amd64 without pushing.
The deployment still needs writable cache and temporary volumes when using a
read-only root filesystem.

[CI](../.github/workflows/main.yaml) runs checks and race-enabled tests against
PostgreSQL 18, verifies generated code, and builds PR images without publishing.
Checks have separate Actions steps; vet, staticcheck and tests run sequentially
rather than competing for runner resources. `mise run check` uses the same order.
Tests disable built-in vet because the full vet check runs separately.
Pushes to `main` publish to
`europe-north1-docker.pkg.dev/nais-io/nais/images/v0s` through
`nais/platform-build-push-sign`, including an SBOM attestation and signing.
The same job packages and pushes the OCI Helm chart to
`oci://europe-north1-docker.pkg.dev/nais-io/nais/feature/v0s`, using the image
version for both the chart version and `appVersion`. Its Actions summary gives
the chart reference, version and image reference with digest for manual Fasit
assignment. No assignment or deployment is created automatically.

Image and chart publication require infrastructure outside this repo:

- `gh-v0s@nais-io.iam.gserviceaccount.com` with
  `roles/artifactregistry.writer` on the `nais` GAR repository.
- GitHub Workload Identity Federation allowing `nais/v0s` to impersonate that
  account with `roles/iam.workloadIdentityUser`. The existing
  `nais/nais-io-terraform-modules` service-account map can express this as
  `gh-v0s = "v0s"`.
- The organization secret `NAIS_IO_WORKLOAD_IDENTITY_PROVIDER` available to this
  GitHub repository. No service-account key is needed.

This publishing identity is separate from the workload's runtime identity and
registry-read permissions. The management module in `nais-terraform-modules`
provisions `v0s-sa` and passes its email to Fasit; no runtime email is configured
manually. This does not change the publishing account.

## Helm deployment

The [chart](../charts/README.md) deploys v0s into the management namespace. Its
`Feature.yaml` requires `nais-api`, `nais-netpols-management`, `cloudnative-pg`,
`fqdn-policy` and `monitoring-crds`. Nais API is the required, sole inventory
source, not an optional integration or a Helm subchart. The feature dependency
does not replace verification of the `Workloads.ListImages` gRPC contract.

New installs provision PostgreSQL through the shared `nais-postgresql` Helm
subchart, not a separate Fasit assignment. The pinned version is 0.2.2. It creates
`v0s-db`; CNPG's `v0s-db-app.uri` is reserved for the migration init container.
The main container uses the separate `v0s-db-appuser.uri` read/write role.
The shared chart provisions both the role and its retained password Secret;
v0s does not duplicate credential generation. Upgrades retain its password.
The pinned dependency is bundled in the
published chart. `nais-netpols-management` supplies namespace-wide DNS and
Kubernetes API egress; v0s needs no API-server or Service-IP CIDR inputs. The
default is three PostgreSQL instances with 10Gi per instance and required node
anti-affinity. Review sizing and eligible nodes before rollout.

To retain an existing independent database, set `postgresqlEnabled=false` and
keep `database.clusterName` unchanged. That mode creates no Cluster and does
not adopt or replace the existing database. Prepare its runtime read/write role
and Secret in the owning release first; the owner Secret remains available only
to the migration init container. This upgrade preserves databases and assessments,
including the pilot; no database reset is part of the rollout.

Managed databases default to `postgresql.keep=true`, retaining the Cluster on
uninstall but not its chart-owned NetworkPolicies. Retention is not protection
against direct or namespace deletion. Backups are disabled in v0s's defaults:
configure and verify recovery separately before
production use. See the chart README for the lifecycle and adoption caveats.

Apply the management module's v0s identity resources through Atlantis before
assigning the chart. The module creates `v0s-sa`, grants
Artifact Registry reader in the management project, binds Workload Identity to
`nais-system/v0s`, and publishes `v0s_serviceaccount_email`. Fasit computes the
chart's `serviceAccountEmail` from this value. Use release `v0s` in `nais-system`;
other names need corresponding identity bindings. There are no Kubernetes API
permissions or service-account keys. Additional private registries may need
separate read grants. Set trusted GitHub organizations and review the
HTTPS egress allowlist for the tenant. See the chart README for rendering and
packaging commands. CI publishes the chart after the signed image, but creating
or updating its Fasit assignment is a separate, manual step. Assign the chart
reference and version from the Actions summary, not the container image URL.

## Runtime configuration

Configuration is read from environment variables by [`cmd/v0s`](../cmd/v0s/main.go).
Run `v0s migrate` with the owner's `DATABASE_URL` before starting the service;
it needs no inventory, registry or scanner configuration. Normal startup uses
the read/write user's URL and checks the schema version without migrating.
The chart handles both commands and keeps owner credentials out of runtime.
Its `Recreate` strategy stops old replicas before migrations, with deliberate
application downtime while the new pod starts.
Fasit also uses Helm's `--atomic` rollback, which does not undo database changes.
Before the first incompatible upgrade, verify a safe rollback revision with
the old app recorded at zero replicas, or arrange an upgrade without automatic
rollback; scaling only the live Deployment is insufficient. Follow the
[upgrade procedure](../charts/README.md#upgrading-an-existing-deployment).

| Variable | Required / default |
|---|---|
| `DATABASE_URL` | Required: PostgreSQL connection URL |
| `NAIS_API_GRPC_ADDRESS` | Required: Nais API's internal gRPC address |
| `GITHUB_ORGANIZATIONS` | Required: comma-separated organizations whose workflow signatures are accepted |
| `LISTEN_ADDR` | `:50051` (plaintext gRPC, with reflection) |
| `PROBE_ADDR` | `:8080` (HTTP probes and metrics) |
| `TRIVY_DB_DIR` | `/var/cache/v0s/trivy-db` |
| `TRIVY_DB_REPOSITORIES` | Comma-separated fallback order; default `mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2` |

Nais API must expose a wire-compatible `Workloads.ListImages`; the client schema
is vendored in [`third_party/naisapi`](../third_party/naisapi/workloads.proto).
Deploy a compatible Nais API before a v0s build that requires it.

The process needs writable storage for the Trivy cache and Sigstore's trust root
under `$HOME/.sigstore`. Registry credentials use the default, Google and GitHub
keychains. Egress must cover the workload registries and their authentication and
redirect hosts, the configured Trivy DB registries, Sigstore, FIRST EPSS and CISA
KEV. A blocked attestation lookup is an error, not evidence that no SBOM exists.

## Simplified public contract

The 2026-11-17 source change simplifies the
[gRPC contract](../proto/v0s/v1/v0s.proto). It is not a deployment or an
implementation of the proposed GraphQL layer in Nais API.

- Read filters take one `team`, or no team for tenant-wide reads. A `workload`
  filter requires `team` and `environment`; `ListWorkloads` now accepts that
  workload filter too. Requests carrying the removed `teams` field fail with
  `InvalidArgument` rather than silently becoming tenant-wide.
- Findings and advisory details expose `known_exploited`, and the finding filter uses
  `only_known_exploited`. CISA KEV is the documented source: false means not
  listed in that catalog, not proof of no exploitation. A valid KEV catalog is
  nonempty and replaced atomically.
  Until one is stored, `ListFindings`, `GetVulnerability` for a known ID, and
  KEV-filtered `CountFindings` fail with `Unavailable`. Absence of a catalog is
  not `false` or zero findings. Ordinary counts, inventory and suppressions do
  not depend on KEV.
- A failed feed refresh retains the last catalog. EPSS and KEV refreshes are
  attempted independently, so an EPSS failure does not block the first KEV
  import. Feed age remains an operational concern, not a new client protocol.
- CVSS is returned only by `GetVulnerability`, as one entry per source/version.
  Versions are `3.0`, `3.1` and `4.0`; `3.x` means a v3 score without a vector
  that identifies its minor version. Both `score` and `vector` have protobuf
  presence. Callers must inspect `Score != nil` before reading it; `GetScore()`
  alone collapses absence to zero. Trivy and older stored records use zero for
  missing scores, so zero is exposed only when a valid zero-impact vector
  confirms it. Missing scores remain absent, including malformed/nonzero-impact
  vectors without a source score. Existing stored CVSS records remain readable.
- The public API no longer exposes finding title/raw fix status/aggregate CVSS,
  source-severity matrices, advisory dates, KEV metadata, EPSS percentile or the
  scanner DB version. Internal source data and scan bookkeeping are retained.

This intentionally breaks generated client/source compatibility. Regenerate
all v0s consumers and coordinate their rollout with the server; do not rely on
old clients interpreting the new response fields. Removed protobuf field
numbers and names are reserved, not reused. Keep rollback builds with matching
clients available. No database migration or reset is required for this contract
change; existing workload-scoped assessments and source data are unchanged.

## Health and diagnostics

`GET /healthz` checks only database connectivity. It does not establish that
inventory sync, scanning or enrichment is working.

`GET /metrics` exposes:

- `v0s_images{sbom,scan}`: in-use images by SBOM and scan state against this
  replica's loaded DB; `scan` is `pending`, `current` or `failed` for fetched SBOMs.
- `v0s_trivy_db_version_timestamp_seconds` and `v0s_trivy_db_updates_total{result}`.
- `v0s_fetches_total{result}`, `v0s_scans_total{result}` and `v0s_scan_duration_seconds`.
- `v0s_enrichment_last_success_timestamp_seconds{feed}`: success on this replica,
  not a cluster-wide heartbeat.
- `v0s_inventory_syncs_total{result}` and
  `v0s_inventory_sync_last_success_timestamp_seconds`: completed sync attempts
  while holding the cluster lock, excluding shutdown cancellations. Skipping a
  held lock does not count as a success. The timestamp is 0 before first success.
- `v0s_grpc_request_duration_seconds{method,code}` and Go/process metrics.

Use loop logs as well as metrics to investigate stalled inventory, growing scan
backlogs, old DBs, failed fetches and enrichment failures. The API exposes
unresolved references, image status and errors; these are coverage information,
not a client-side freshness protocol.

## Grafana dashboard

[`grafana/v0s.json`](../grafana/v0s.json) follows the
[`nais/cli` example](https://github.com/nais/cli/tree/main/grafana): a
`dashboard.grafana.app/v1` resource, read-only in Grafana, with Git as the source.
In [management Grafana](https://monitoring.nais.io/d/v0s), select the tenant's
`*-metrics` datasource, cluster and discovered scrape job. NAV is the default.
Cluster filtering uses the management stack's `k8s_cluster_name` label.
The single-select scrape job uses an exact label match: Grafana's `:regex`
formatter escapes `/` in jobs such as `nais-system/v0s`, which PromQL rejects
as an invalid string escape.

The [handbook's Git Sync setup](https://handbook.nais.io/technical/observability/#grafana-dashboards)
requires this repository to be accessible to the `grafana-git-sync` GitHub App.
It syncs `grafana/` from the default branch. The file must be merged there before
it appears; no Helm ConfigMap or manual dashboard upload is needed. The two
inventory metrics also require a rollout of the updated binary.

Read the dashboard in this order:

1. **Serving and freshness:** scrape availability, last inventory sync, oldest
   loaded vulnerability DB, unloaded replicas, and independent EPSS/KEV sync ages.
2. **Images:** current state, backlog and missing/failed images. These three panels
   use only the selected snapshot replica, since all replicas count the same
   database and may have different loaded DB versions. Counts are images, not
   workloads; unresolved image references are not included.
3. **Processing and dependencies:** fetch/scan outcomes, scan latency, sync
   outcomes, per-replica DB age and update checks, and enrichment age.
4. **gRPC and process:** requests, service errors, response codes, p95 latency,
   CPU, RSS, goroutines and uptime.

Yellow/red freshness thresholds are investigation aids, not alert rules or SLOs:
inventory 5m/15m, loaded DB age 48h/72h, enrichment 30h/48h. Inventory and feed
success timestamps are replica-local, so the dashboard takes the latest observed
success across live replicas. Restarting all replicas loses those observations,
not the stored inventory or feeds. An inventory success means the returned
snapshot was applied; it does not prove the upstream snapshot was complete.

No data is not rendered as a healthy zero. In particular, `/metrics` can respond
while the image collector fails its database query. Check logs if image panels
are empty while target availability is healthy. Most existing outcome counters
only create a result series after its first event; rates need at least two
scrapes. All rate panels use a 1m minimum interval for the chart's 1m scrape
cadence. Scan/fetch outcomes are counted before their database writes.

The service-error ratio counts `Unknown`, `Internal`, `Unavailable` and `DataLoss`.
Other non-OK codes, including cancellations and deadlines, remain visible in the
response-code panel. An idle method has no error percentage, not 0%. Process RSS
is not container memory headroom; use Kubernetes/CNPG metrics for resource limits,
OOMs, database replication and recovery.

## Retries and recovery

- Each image's registry and attestation operations receive a shared two-minute
  deadline, including bundle-to-legacy fallback. Fetches still run in batches of
  16, so a slow registry request can delay the next batch until its deadline.
  Credential resolution uses the service context: cached token sources must
  survive individual fetches. External credential helpers have their own timeout
  behavior and are not force-stopped by the per-image deadline.
- Missing attestations are retried after 6 hours; failed fetches, including local
  timeouts, after 30 minutes. Shutdown cancellation leaves the image due without
  recording a failure.
- Failed loops retry after the shorter of their normal interval and 5 minutes.
- A recorded scan failure is not retried until a newer DB is loaded. Previous
  findings are kept; an already scanned image stays `SCANNED` with an error.
- A scan interrupted without a recorded outcome can be attempted three times per
  image/DB version, then is marked failed. A newer DB makes it eligible again.
- Restarting a replica does not clear recorded failures or force rescans.

Postgres is not disposable in production. Inventory, SBOMs and scan results can
be rebuilt from external sources; suppressions cannot. Back up the database and
verify recovery of the assessments. A caller's activity log is not a substitute.

## Pilot and remaining validation

The [archived manual manifest](archive/dev-nais-manual-manifest.yaml) records
the historical manual pilot, not the current app installation. It uses
`v13s-sa`, one PostgreSQL 18 instance and no backups; do not bulk-delete it,
because it also defines the database. The [manual deployment verification](archive/dev-nais-deploy-2026-11-06.md)
is a historical snapshot.

On 2026-11-06, Fasit took over the dev-nais app with the dedicated `v0s`
runtime identity, initially retaining the independent pilot database.
Session verification on 2026-11-09 subsequently observed chart-managed CNPG
provisioning and working read APIs in both dev-nais and NAV at
`2026-11-09-115640-d881a93`. Dev-nais also exercised a temporary suppression
write/read/delete. The database provisioning and later network-policy rollout
are therefore no longer untested; backup/restore and failure recovery remain
unverified. See the [dated consolidated evidence](status-2026-11-10.md).

The 2026-11-10 NAV comparison still observed `d881a93`, without the later
pagination and fetch/credential fixes. Local tests of those fixes are not
live validation. These are dated observations, not a fresh deployment check.

Schema changes now use forward migrations; do not reset a database to upgrade it.
`0002_workload_suppressions.sql` preserves old team/image assessments in
`legacy_suppressions` and copies them to each currently resolved workload with
the same team and image name. It preserves state, reason, actor and timestamp.
Unmatched or unresolved workloads receive no inferred assessment; their originals
remain in the legacy table for manual review. Migration runs once, transactionally.
Copied assessments are independent and should be reviewed in each workload's
context; the original decision did not distinguish those contexts.

Back up before upgrading and compare the old records, copied workload assessments
and unmatched originals afterwards. Inventory completeness at migration time
determines which assessments can be copied. Later syncs do not propagate legacy
assessments. Do not mix old and new binaries: stop old replicas before starting
the upgraded service, because old queries and writes lack workload scope. The
current chart enforces this for its Deployment and runs `v0s migrate` first;
stop any separately managed old pods before upgrading as well.
Update clients to supply environment and workload for set/delete calls;
requests missing them are rejected, and old suppression page tokens must be
discarded. Rolling back requires a coordinated schema/data recovery; old binaries
must not be pointed at the new schema.

The comparison tool still targets the old API; see
[`tools/compare`](../tools/compare/README.md). Live multi-replica failures, recovery
and tenant-scale performance remain to be verified using the
[verification checklist](verification.md).

Known integration/security follow-ups:

- Attestation identity checks match the workflow certificate SAN, not the source
  repository owner. A public reusable workflow can make these differ; see the
  TODO in [`internal/attest`](../internal/attest/attest.go).
- Console assessment states still need mapping to v0s's three suppression states.
- Missing packages in source SBOMs limit coverage; a successful scan is not proof
  that every package or runtime binary was represented.
- An earlier pilot session printed a v13s database password in terminal output.
  Confirm that it has been rotated; the archived handover records the incident.
