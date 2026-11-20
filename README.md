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
Run `mise run generate` after changing protobufs. `mise run build` writes
`bin/v0s`; `mise run build:image` builds a local Linux image without pushing.
Green builds on `main` publish signed images and Helm charts to GAR, then assign
the chart through Fasit to `ci-nais` management with a wait for success before
assigning all management environments.

## Documentation

[Visual team pitch](docs/pitch.html) ·
[Developer contract proposal](docs/utviklerkontrakt.md) ·
[Collected work and evidence (2026-11-10)](docs/status-2026-11-10.md) ·
[Documentation and session-source index](docs/README.md)

[Domain language](CONTEXT.md) · [Architecture](docs/architecture.md) ·
[Operations](docs/operations.md) · [Verification](docs/verification.md) ·
[Helm chart](charts/README.md)

Historical proposals, measurements and session notes are in the [archive](docs/archive/README.md).
