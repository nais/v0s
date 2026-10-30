# v0s

v0s reports which known vulnerabilities affect the container images running in a
Nais tenant. It reports mechanical facts and no judgements.

It replaces v13s together with Dependency-Track. The motivation is recorded in
the session notes (`~/ws/sessions/v13s-veien-videre`).

## What it does

1. Watches running pods in the tenant's clusters and records which image digests
   run where.
2. Fetches the attested CycloneDX SBOM for each digest and verifies its signature.
   The image itself is never pulled.
3. Matches the SBOM against the Trivy vulnerability database, in-process, using a
   local copy of the database.
4. Rescans every image in use whenever a new database is published.
5. Serves the results through a gRPC API (`v0s.v1`): findings, components and
   tenant-wide package search, counts, finding events, and suppressions.

## What it does not do

- It computes no priority, risk score or "top" lists. Clients decide what
  matters. v0s exposes the inputs: severity and its source, CVSS, fix version,
  fix status, EPSS and KEV.
- It does not write to any other system. Suppressions are owned here.
- It does not share data across tenants. There is one v0s per tenant.

## Principles

- Facts in, facts out. Every field can be traced to the SBOM, the Trivy DB,
  FIRST EPSS, CISA KEV or a human decision (suppression).
- The system converges toward the desired state (level-triggered). Loops compare
  desired state with actual state in Postgres. There are no event queues to
  lose.
- Postgres is the only state. Replicas are interchangeable, and work is claimed
  with `FOR UPDATE SKIP LOCKED`.
- Few dependencies. Use the standard library first.

See `CONTEXT.md` for the domain language and `docs/adr/` for decisions.

## Development

```sh
mise install
make generate   # protobuf
make check      # vet, staticcheck, tests (needs postgres binaries on PATH)
```
