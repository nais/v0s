# dev-nais deployment, 2026-11-06

## Scope and versions

Manual pilot upgrade in `dev-nais-management-v2`, namespace `nais-system`.
Only v0s and its disposable database were changed; v13s and nais-api were not
modified. The operator explicitly approved wiping the existing pilot database.

- Source: clean checkout of `97a170f` on `main`.
- Image tag: `europe-north1-docker.pkg.dev/nais-io/nais/images/v0s:97a170f-manual`.
- Deployed digest: `sha256:3ca6aa3e3ac0154bc182ea8c0fbe398cc88b569337fea5e8f335ecdb68f62cc3`.
- Base: `gcr.io/distroless/static-debian13:nonroot`, linux/amd64 digest
  `sha256:336e53e9941facdb69b755e6fd2c63f5400abd3b1ba47bb17ebafc2b1547cebd`.
- nais-api already ran the official `2026-11-06-113158-4cb3e0d` image. PR #609
  was merged; its `Workloads.ListImages` schema matches the vendored client.
- Loaded Trivy DB: `2026-11-06T09:50:00.021603275Z`, artifact digest
  `sha256:84a5dc1a8ba53da65eeb172ff058b8b3c296706d60bb2f97295f2b20a9a1414b`.

## Build and rollout

Docker was not running, and the repository has no Dockerfile. The binary was
cross-compiled locally with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
-trimpath -ldflags='-s -w'`, then added to the pinned distroless base with
`crane mutate` 0.22.1. Entrypoint `/v0s`, user `65532:65532`; image labels record
the source repository and revision. This is a manual pilot image, not a signed
CI release or an attested build.

`make check` and `go test -race -count=1 ./...` passed, using the PostgreSQL
installation configured in `mise.local.toml` for database tests.

After a successful server-side dry run:

1. Scaled v0s to zero and waited for its pod to stop.
2. Deleted the `v0s-db` CNPG Cluster and waited for its owned PVC `v0s-db-1`
   to disappear. All previous pilot data was discarded.
3. Applied the manifest's `nais-system`-only ingress rule to NetworkPolicy
   `v0s` **before** starting the unauthenticated build. Previously this policy
   listed only egress.
4. Applied `deploy/dev-nais/management.yaml`, recreating the database and
   deploying the new digest.
5. Waited for the database Ready condition and successful Deployment rollout.

## Live verification

Checked around `2026-11-06T12:36Z` through temporary localhost port-forwards to
v0s, using the current generated Go client with plaintext gRPC and **no token**.
The first read during cold start was empty; subsequent reads after inventory
sync and scanning returned the results below. Readiness alone was not used as
proof of successful reconciliation.

- Deployment: 1/1 Ready, running the new digest.
- `/healthz`: HTTP 200.
- `ListWorkloads`: eight workloads, with `image_reference`, `Image.status`, scan
  timestamps and `resolve_error` as appropriate.
- Two distinct images successfully scanned, used by three workloads; three
  additional images reported `NO_SBOM`. No pending or failed images remained
  among the resolved images at the snapshot.
- Two unresolved workloads remained visible instead of being omitted.
- `ListFindings`: three findings on `nais-verification/kafka-canary`, with
  workload references and scanned image status.
- `CountFindings` by severity: `UNKNOWN = 3`, consistent with the listing.
- `SearchComponents` for `pkg:golang/stdlib`: two image matches, including the
  shared testapp image with both workloads listed.
- `ListSuppressions`: successful, zero suppressions after the wipe.
- Metrics: `v0s_scans_total{result="ok"} = 2`, fetched/current = 2,
  missing = 3, pending = 0, failed = 0. EPSS and KEV both recorded successful
  enrichment.
- Live NetworkPolicy configuration restricts ingress to `nais-system` and
  preserves the declared database, nais-api and metadata-server egress. No
  cross-namespace traffic test was performed.

### Workload snapshot

All workloads are in environment `dev`. Repository names below are under
`europe-north1-docker.pkg.dev/nais-io/nais/images/` unless otherwise stated.

| Team/workload | Image | Observed state |
|---|---|---|
| `basseng/foo.baz` | `nginx:latest` | Unresolved: GAR returns 404 |
| `johnny/jobb` | `testjob:latest` | `NO_SBOM` |
| `johnny/johnny` | `testapp:latest` | `SCANNED` |
| `nais-verification/kafka-canary` | `kafkarator/canary:20261022110324-acaaa1b` | `SCANNED`, three findings |
| `nais-verification/nais-deploy-canary` | `deploy:20261102135106-033f70f` | `NO_SBOM` |
| `test-digest/debug-2` | `docker.io/library/nginx:latest` | `NO_SBOM` |
| `tommy/debug` | `testapp:latest` | `SCANNED`, shares image with `johnny/johnny` |
| `tommy/mock-oauth-server` | `ghcr.io/navikt/mock-oauth2-server:4.0.0` | Unresolved: registry request timed out |

Resolved image digests:

| Image | Digest |
|---|---|
| `testjob` | `sha256:262329809667f1b3f7aafb3209c6741c62e9ab558236464008ab541ab4b96feb` |
| `testapp` | `sha256:bd06e3157a3a9e482dd41dda8948c3ab41b4270913916e69fdd6681ab056b88a` |
| `kafkarator/canary` | `sha256:4977648777bf119266a8d258485dcbd469ce3e64d545a3106dc234d192468e2c` |
| `deploy` | `sha256:8bb156fe00047df11643361b8455c9333310def5eabfa62435190972eca0b77f` |
| `docker.io/library/nginx` | `sha256:165ddde8751e75a1c907d24ef10d9f6deb08b57e0fe56caf67512486aff76d82` |

The findings were `CVE-2026-78661`, `CVE-2026-97045` (both
`pkg:golang/golang.org/x/net@v0.61.0`) and `GO-2026-5932`
(`pkg:golang/golang.org/x/crypto@v0.58.0`), all from `govulndb` with UNKNOWN
severity and a fixed version reported.

## Remaining work

The GAR 404 and GHCR timeout are coverage gaps, not evidence that those workloads
are safe. Registry retries continue through the normal sync loop. Suppression
writes, cross-namespace policy enforcement, multi-replica failures, recovery and
scale were not tested in this rollout. The comparison tool still needs updating
before comparing with v13s/Dependency-Track.
