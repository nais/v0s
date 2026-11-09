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
subchart, not a separate Fasit assignment. It creates `v0s-db` and CNPG supplies
`v0s-db-app.uri` for the application. The pinned dependency is bundled in the
published chart. `nais-netpols-management` supplies namespace-wide DNS and
Kubernetes API egress; v0s needs no API-server or Service-IP CIDR inputs. The
default is three PostgreSQL instances with 10Gi per instance and required node
anti-affinity. Review sizing and eligible nodes before rollout.

To retain an existing independent database, set `postgresqlEnabled=false` and
keep `database.clusterName` unchanged. That mode creates no Cluster and does
not adopt, replace or migrate the existing database. For the disposable dev-nais
pilot, the operator has instead approved deleting the old database and testing
fresh chart provisioning; follow the chart README's scoped reset procedure.
This approval does not apply to NAV.

Managed databases default to `postgresql.keep=true`, retaining the Cluster on
uninstall but not its chart-owned NetworkPolicies. Retention is not protection
against direct or namespace deletion. Neither this chart nor the database
subchart configures backups: configure and verify recovery separately before
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
- `v0s_grpc_request_duration_seconds{method,code}` and Go/process metrics.

Use loop logs as well as metrics to investigate stalled inventory, growing scan
backlogs, old DBs, failed fetches and enrichment failures. The API exposes
unresolved references, image status and errors; these are coverage information,
not a client-side freshness protocol.

## Retries and recovery

- Missing attestations are retried after 6 hours; failed fetches after 30 minutes.
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

On 2026-11-06, Fasit took over the dev-nais app using version
`2026-11-06-155111-44f64ee` and the dedicated `v0s` runtime identity. The existing
CNPG Cluster and PVC retained their identities and remained outside the app
release. Database-subchart provisioning has not been deployed or runtime-tested.
NAV's initial app assignment was blocked by missing `v0s-db-app`; provisioning
is intended to address that gap, not evidence that NAV is already operational.

The pre-release `0001_schema.sql` is edited in place. If it changes again, an
existing pilot database needs a reset to receive those changes. Confirm its
suppressions are disposable before resetting; never apply that recovery model
to production.

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
