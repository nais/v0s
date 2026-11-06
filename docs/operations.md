# Operations

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

[`deploy/dev-nais/management.yaml`](../deploy/dev-nais/management.yaml) is a manual
pilot manifest, not a production deployment template. It uses `v13s-sa`, one
PostgreSQL 18 instance, no backups, and pins an older v0s image. Do not assume it
runs the current API. No release workflow or Helm chart exists in this repo yet.

Before the next comparison, publish a current build and update the pilot image.
The pre-release `0001_schema.sql` was edited in place, so an existing pilot database
needs a reset to receive those changes. Confirm its suppressions are disposable
before resetting; never apply that recovery model to production.

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
