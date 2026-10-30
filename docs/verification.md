# Running v0s next to v13s and verifying it

Goal: run v0s in a real tenant, read-only and without consumers, so that we can
look at the findings it produces for real workloads, compare them with v13s, and
measure how it behaves and performs. Start in `dev-nais`, then `nav`.

## Shape

v0s runs the way v13s does: a Fasit feature in the tenant's management cluster,
watching the tenant clusters through their API servers with a Google service
account. Nothing calls it except the people verifying it. v13s is untouched.

```
management cluster (nais-system)                     tenant cluster(s)
  v0s (1 → 2 replicas) ── Pods list/watch ─────────▶  apiserver.<env>.<tenant>.cloud.nais.io
   │  │  └─ attestations ──▶ registries (GAR, ghcr)
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
| helm-charts | `features/v0s-rbac`: ClusterRole pods get/list/watch bound to `v0s-sa@<management project>`, `targets.json` = dev-nais `tenant` | dev-nais only |
| v0s | Dockerfile, chart (`charts/` with `Feature.yaml`), metrics, gRPC reflection | this repo |

The chart follows v13s: one Deployment, own KSA
`v0s-sa`, NetworkPolicy plus FQDNNetworkPolicy listing the hosts above,
read-only root filesystem with an `emptyDir` (sizeLimit 4Gi) for the Trivy DB,
ServiceMonitor, gRPC ingress. Access is the existing Google ID-token check; the
allowed service accounts are `v0s-sa` itself (people impersonate it, as with
v13s's `vulnz`) and later the nais-api account.

Postgres: the chart depends on `nais-postgresql` (helm-charts `charts/`, published
to `oci://europe-north1-docker.pkg.dev/nais-io/nais/chart`), which adds a
CloudNativePG cluster to the v0s release using the `cloudnative-pg` operator
feature already running in management clusters. v0s reads `DATABASE_URL` from the
generated `v0s-db-app` Secret. PostgreSQL 18, the version the tests run against.
One instance in dev-nais: the data can be rebuilt from the clusters and
registries, and the chart configures no backups. Load and storage belong to v0s
alone, and nothing we do can affect v13s.

## What v0s needs before deploying

- Dockerfile (distroless, nonroot).
- Prometheus metrics on the probe listener, enough to answer the questions below:
  - `v0s_scan_duration_seconds` histogram, `v0s_scans_total{result}`
  - `v0s_fetches_total{result="found|not_found|error"}`
  - `v0s_images{sbom="pending|fetched|missing|failed",scan="pending|current|failed"}` counted in the database at scrape time
  - `v0s_trivy_db_version_timestamp_seconds`, `v0s_trivy_db_updates_total{result}`
  - `v0s_enrichment_last_success_timestamp_seconds{feed}`
  - `v0s_grpc_request_duration_seconds{method,code}`
  - Go runtime and process collectors (memory, CPU, goroutines)
- gRPC server reflection, so `grpcurl` works without the proto files.
- A cap on scan attempts per image (open item from review 2): an SBOM that kills
  the process must not crash-loop every replica. Count claims, record a failure
  after three.

Not needed for dev-nais, needed for nav: static clusters (on-prem `fss` with
token credentials, as v13s supports) and nav's `legacy` environment kind in the
Fasit cluster list.

## Verification

Each check states what we look at and what counts as acceptable. Results go in
the session notes with the image/DB versions used.

### Output: findings per workload

1. For every workload in the tenant, fetch findings from both systems and compare
   on (image digest, package purl, canonical vulnerability ID):
   - v0s: `grpcurl … v0s.v1.VulnerabilityService/ListFindings` per workload.
   - v13s: `vulnz` with the same workload.
   A small comparison script (kept with the session notes, not in this repo) prints
   matched / v0s-only / v13s-only per workload and severity.
2. Inspect every critical/high difference by hand and classify it (advisory
   withdrawn, different source, purl/version mismatch, real miss). Accept when no
   unexplained critical/high difference remains.
3. Coverage: share of running images with a verified SBOM, and the reasons for the
   rest (`missing`, `failed`), compared with v13s for the same images.
4. Package search: look up a package known to run (e.g. `pkg:golang/stdlib`) and one
   with no finding; both must list the workloads using it.
5. Suppressions: dry-run, create, list, revoke through grpcurl on a real finding;
   the finding's suppression state and counts change accordingly.

### Behaviour

| Scenario | Expected |
|---|---|
| Deploy a new version of a test app | findings for the new digest within sync + fetch + scan time; old digest leaves the workload |
| Delete the app | its images leave the workload set; image rows are collected after 30 days |
| Image without attestation | `missing`, retried on a backoff, no retry storm |
| Trivy DB update (about every 6 h) | every image rescanned once; `v0s_scans_total` rises by the image count, not more |
| Two replicas | no image scanned twice for the same DB version; one watcher leader |
| Kill a pod during a scan | the image is picked up again after the lease; no lost or duplicated findings |
| Postgres pod restart, apiserver or registry unreachable, EPSS/KEV feed down | loops log and retry; stored data stays; `/healthz` reflects the database only |

### Performance

Measured from v0s metrics and the CNPG PodMonitor, recorded per tenant:

- cold start: pod start → DB downloaded → backlog (`pending`) at zero;
- per-scan duration p50/p99 and peak memory (`container_memory_working_set_bytes`);
- full rescan after a DB update: duration, CPU, Postgres CPU/IO;
- database size after a week, and growth per rescan (finding events);
- gRPC latency for `ListFindings`, `CountFindings` and `SearchComponents` with real filters.

dev-nais is small; it verifies correctness and behaviour, not scale. Scale is
measured in nav (about 4,100 Dependency-Track projects), in the same shadow mode, after dev-nais
passes.

## Order

1. v0s: Dockerfile, metrics, reflection, attempt cap.
2. Repo on GitHub and `gh-v0s`; CI publishes image and chart. The deploy job targets
   dev-nais management only (no ci-nais canary) and is switched on after step 3.
3. Terraform (dev-nais) and `v0s-rbac` (dev-nais), as draft PRs; read the Atlantis plan.
4. Deploy to dev-nais with one replica; run the output checks.
5. Two replicas; run the behaviour checks; one week of performance data.
6. nav: static clusters, then the same in shadow mode.

Removing it is the reverse: remove the Fasit targets, `v0s_enabled = false`. The
CNPG cluster is kept on uninstall (`keep: true`); delete it explicitly.
