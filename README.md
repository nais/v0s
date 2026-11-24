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

## Documentation

[Documentation index](docs/README.md) ·
[Developer contract proposal](docs/utviklerkontrakt.md) ·
[API, CLI and Console proposal](docs/api-cli-console-forslag.html)

[Domain language](CONTEXT.md) · [Architecture](docs/architecture.md) ·
[Operations](docs/operations.md) · [Verification](docs/verification.md) ·
[Helm chart](charts/README.md)

The developer contract and client proposal are design material, not implemented
client features or evidence of a completed cutover.
