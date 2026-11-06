# Running v0s next to v13s and verifying it

Goal: run v0s in a real tenant, read-only and without consumers, so that we can
look at the findings it produces for real workloads, compare them with v13s, and
measure how it behaves and performs. Start in `dev-nais`, then `nav`.

## What the proof of concept decides

Whether v0s can replace both v13s and Dependency-Track. Agreed boundaries:

- **Correct means classified, not equal to DT.** DT is not ground truth. Every
  critical/high difference is classified by hand: v0s wrong, v13s/DT wrong, or a
  defensible source difference.
- **Facts, not judgments.** Nais does not judge severity or priority. Priority
  tiers, risk score, its trend and the top list are dropped, also from Console.
  Severity is the advisory source's. Ingress exposure is a workload fact nais-api
  already has. nais-api and Console are not changed in the PoC: we verify the
  findings and the API that serves them, and the consumers follow from a solid
  facts API.
- **Unfixed findings are shown** with their status (affected, will_not_fix,
  fix_deferred). DT hides them (`ignore_unfixed`), so the comparison reports
  them separately.
- **Inventory is what is deployed**: the images of Nais applications and jobs as
  Nais API reports them, whether or not they run right now, so apps scaled to zero
  and jobs between runs are included, as in v13s.
- **No history or freshness protocol.** Trend graphs and mean time to fix are
  dropped; v0s serves current state only. Callers do not check inventory age or a
  target scan DB version. Updating the results is v0s's operational responsibility;
  the behaviour checks below verify the loops, not a new client-facing contract.
- **Mutable tags are not tracked.** A tag is resolved once while in use. Pushing a
  different image to the same tag is not expected to update v0s's results.
- **EPSS and KEV stay.** They are source data from FIRST and CISA, not our own
  prioritization or risk calculation.
- **Suppressions**: only new ones through the v0s API. Moving v13s's
  suppressions (versioned purl to versionless key) comes later.
- **SBOM gaps** (customer SBOMs without OS packages, binaries outside a package
  manager) are measured, not fixed. They affect v13s and v0s alike.
- **Dependency paths** (direct or transitive) are not served yet. SBOMs are
  retained, so they can be added without refetching.
- **Trivy DB**: taken from the Nais registry's GitHub pull-through cache as
  published. v0s logs the digest of every DB it loads or swaps in, and every
  scan records its DB version, so each finding traces back to an artifact digest.
  Verifying the DB's signature is a separate item.
- **Performance** is measured and judged together while we run it, not against
  budgets set in advance.
- **Scale**: dev-nais shows behaviour; nav shows scale. Nais API covers all of
  nav's environments, on-prem fss included.

## Shape

v0s runs the way v13s does: a Fasit feature in the tenant's management cluster.
It reads the tenant's workloads from Nais API in the same namespace and needs no
access to the tenant clusters. Nothing calls it except the people verifying it.
v13s is untouched.

```
management cluster (nais-system)
  v0s (1 → 2 replicas) ── gRPC Workloads.ListImages ──▶ nais-api :3001 (workloads of every environment)
   │  │  └─ tag lookups, attestations ──▶ registries (GAR, ghcr, Docker Hub)
   │  └─ Trivy DB ─────────▶ europe-north1-docker.pkg.dev/nais-io/github-ptc/aquasecurity/trivy-db:2
   ├─ EPSS/KEV ───────────▶ epss.empiricalsecurity.com, www.cisa.gov
   ├─ Postgres 18: CloudNativePG cluster in the same release (nais-postgresql chart)
   ├─ gRPC  ◀── ingress v0s.<tenant>.cloud.nais.io (naisdevice) ◀── grpcurl / compare script
   └─ :8080 /healthz /metrics ◀── ServiceMonitor
```

The Trivy DB pull-through cache already exists and serves the same digest as
`ghcr.io/aquasecurity/trivy-db:2` without credentials, so we mirror nothing ourselves.

## What has to exist

| Where | What | Scope |
|---|---|---|
| GitHub | public `nais/v0s` repo, workflow: test, build/push/sign image, push chart to `oci://europe-north1-docker.pkg.dev/nais-io/nais/feature`, `fasit-deploy` with targets `dev-nais` management only | new repo |
| nais-io-terraform-modules | `gh-v0s` publisher service account for the repo | nais.io |
| nais-terraform-modules | `modules/management/v0s.tf` behind `v0s_enabled` (default false): `v0s-sa` with Workload Identity and `artifactregistry.reader`, Fasit value `v0s_serviceaccount_email`; set `v0s_enabled = true` in `tenants/dev-nais` | dev-nais only (Atlantis plan must show no change elsewhere) |
| nais/api | `Workloads.ListImages` on the internal gRPC API; in dev-nais a local build, not upstream | dev-nais only |
| v0s | Dockerfile, chart (`charts/` with `Feature.yaml`), metrics, gRPC reflection | this repo |

The chart follows v13s: one Deployment, own KSA
`v0s-sa`, NetworkPolicy plus FQDNNetworkPolicy listing the hosts above,
read-only root filesystem with an `emptyDir` (sizeLimit 4Gi) for the Trivy DB,
ServiceMonitor. The API has no authentication: NetworkPolicy admits only
`nais-system`, as for Nais API's internal gRPC API. People reach it with
`kubectl port-forward`.

Postgres: the chart depends on `nais-postgresql` (helm-charts `charts/`, published
to `oci://europe-north1-docker.pkg.dev/nais-io/nais/chart`), which adds a
CloudNativePG cluster to the v0s release using the `cloudnative-pg` operator
feature already running in management clusters. v0s reads `DATABASE_URL` from the
generated `v0s-db-app` Secret. PostgreSQL 18, the version the tests run against.
One instance in dev-nais, with no backups. Inventory and scan results can be
rebuilt from Nais API, the registries and Trivy, but suppressions are durable human
assessments owned by v0s and cannot be rebuilt from those sources. The pilot treats
its test suppressions as disposable; production backup and recovery must preserve
them. A pilot reset loses them. Load and storage belong to v0s alone, and nothing
we do can affect v13s.

## Built for the pilot

The Dockerfile (distroless, nonroot), gRPC server reflection, and a cap of three
scan attempts per image and DB version are in place, so an SBOM that kills the
process cannot crash-loop every replica. Prometheus metrics on the probe listener:

- `v0s_scan_duration_seconds` histogram, `v0s_scans_total{result}`
- `v0s_fetches_total{result="found|not_found|error"}`
- `v0s_images{sbom="pending|fetched|missing|failed",scan="pending|current|failed"}` counted in the database at scrape time
- `v0s_trivy_db_version_timestamp_seconds`, `v0s_trivy_db_updates_total{result}`
- `v0s_enrichment_last_success_timestamp_seconds{feed}`
- `v0s_grpc_request_duration_seconds{method,code}`
- Go runtime and process collectors (memory, CPU, goroutines)

The dev-nais pilot runs ahead of the chart and Terraform: `deploy/dev-nais/management.yaml`
is applied by hand and runs as v13s's KSA `v13s-sa`, so it needs no new Google service
account. Until the first release the schema lives in one migration that is edited in
place; an existing pilot database is reset by recreating its CNPG cluster.

## Verification

Each check states what we look at and what counts as acceptable. Results go in
the session notes with the image/DB versions used.

### Output: findings per workload

1. Fetch findings from both systems and compare on (image digest, package purl,
   canonical vulnerability ID):
   - v0s: `grpcurl … v0s.v1.VulnerabilityService/ListFindings`; one finding per
     workload.
   - v13s: `vulnz` per workload.
   A small comparison script (kept with the session notes, not in this repo) prints
   matched / v0s-only / v13s-only per workload and severity, with v0s-only unfixed
   findings counted separately.
2. Inspect every critical/high difference by hand and classify it: v0s wrong,
   v13s/DT wrong (for example a withdrawn advisory or package misattribution), or a
   defensible source difference. Done when no critical/high difference is unclassified.
3. Coverage: share of workloads whose image is `scanned`, and the reasons for the
   rest (unresolved image, `no_sbom`, `failed`, `pending`), compared with v13s for the
   same workloads.
4. Package search: look up a package known to run (e.g. `pkg:golang/stdlib`) and one
   with no finding; both must list the workloads using it.
5. Suppressions: set, replace, list and delete new suppressions through grpcurl on a
   real finding; the finding's suppression and the counts change accordingly, for the
   team's own workloads only.
6. SBOM gaps: count images whose SBOM has no OS packages, and runtime binaries that
   the SBOM misses (spot-check with a direct image scan).

### Behaviour

| Scenario | Expected |
|---|---|
| Deploy a new version of a test app | findings for the new digest within sync + fetch + scan time; old digest leaves the workload |
| Delete the app | its image and findings are deleted at the next sync, unless another workload uses it |
| Image without attestation | `missing`, retried on a backoff, no retry storm |
| Trivy DB update (about every 6 h) | every image rescanned once; `v0s_scans_total` rises by the image count, not more |
| Two replicas | one fetches and scans, both serve the API; no image scanned twice for the same DB version |
| Kill a pod during a scan | another replica, or the restarted pod, scans the image again; no lost or duplicated findings |
| Postgres pod restart, Nais API or registry unreachable, EPSS/KEV feed down | loops log and retry; stored data stays; `/healthz` reflects the database only |

### Performance

Measured from v0s metrics and the CNPG PodMonitor, recorded per tenant:

- cold start: pod start → DB downloaded → backlog (`pending`) at zero;
- per-scan duration p50/p99 and peak memory (`container_memory_working_set_bytes`);
- full rescan after a DB update: duration, CPU, Postgres CPU/IO;
- database size after a week, and growth per rescan;
- gRPC latency for `ListFindings`, `CountFindings` and `SearchComponents` with real filters.

dev-nais is small; it verifies correctness and behaviour, not scale. Scale is
measured in nav (about 4,100 Dependency-Track projects), in the same shadow mode, after dev-nais
passes.

## Order

1. v0s: Dockerfile, metrics, reflection, attempt cap. Done.
2. Repo on GitHub and `gh-v0s`; CI publishes image and chart. The deploy job targets
   dev-nais management only (no ci-nais canary) and is switched on after step 3.
3. Terraform (dev-nais) as a draft PR; read the Atlantis plan. nais-api with
   `Workloads.ListImages` in dev-nais.
4. Deploy to dev-nais with one replica; run the output checks.
5. Two replicas; run the behaviour checks; one week of performance data.
6. nav in shadow mode, all environments.

Removing it is the reverse: remove the Fasit targets, `v0s_enabled = false`. The
CNPG cluster is kept on uninstall (`keep: true`); delete it explicitly.
