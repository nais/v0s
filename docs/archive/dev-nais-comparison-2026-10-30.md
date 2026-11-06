# v0s in dev-nais: manual deployment and first comparison

> **Historical (2026-10-30).** This describes the first, Pod-watching pilot with
> Google ID-token auth. v0s now takes inventory from Nais API, has no auth, and
> its API reports `Image.status`/`error` instead of SBOM state. `compare.py` still
> targets the old API and must be updated before the next comparison; see
> `docs/handover.md`. `compare-out/` is generated and ignored by git.

Status 2026-10-30: running in `dev-nais-management-v2`, namespace `nais-system`,
applied by hand from `~/ws/github.com/nais/v0s/deploy/dev-nais/` (repo commit
eab8e94, image `europe-north1-docker.pkg.dev/nais-io/nais/images/v0s:eab8e94-manual`,
`sha256:5ed10e7e…`). Runs as v13s's KSA `v13s-sa` (GSA
`v13s-sa@nais-management-7178.iam.gserviceaccount.com`); Pod-read RBAC
`v0s-pod-reader` applied to `dev-nais-dev`. Database: CNPG cluster `v0s-db`
(PostgreSQL 18, one instance, storageClass `dynamic-rwo`).

Remove: `kubectl --context dev-nais-management-v2 delete -f management.yaml`,
`kubectl --context dev-nais-dev delete -f tenant-rbac.yaml`, delete the image tag.

## What it took

- `standard-rwo` (pd-balanced) cannot attach to the n4 nodes in management;
  `dynamic-rwo` works.
- Sigstore caches its TUF root in `$HOME/.sigstore`; with a read-only root
  filesystem `HOME` must point at a writable volume.
- nais-system denies egress by default. Besides the obvious hosts, v0s needs
  every registry that workload images come from (Docker Hub, gcr.io, quay.io,
  registry.k8s.io → us-central1-docker.pkg.dev, …); otherwise attestation lookups
  time out and images end up `failed` instead of `missing`.

## First run (dev cluster)

- Trivy DB swapped in from the GAR github-ptc mirror about 2.5 min after start
  (`sha256:3b203bb7…`, version 2026-10-30T07:16Z). EPSS and KEV loaded.
- 43 workloads (Pods with an `app` label), 47 images: 11 with SBOM, all scanned
  (about 13 ms per scan), 22 without attestation, 14 failed before egress was
  opened (retried on backoff). RSS about 127 MB.
- Pods without an `app` label (kube-system, cnrm-system, CNPG instances in team
  namespaces) are not workloads; this is intended.

## Comparison with v13s (compare.py)

Run: port-forward v0s :15051 and v13s :13001, ID tokens impersonating
`v13s-sa` (audience v0s) and `nais-api` (audience v13s), then `python3 compare.py dev`.

- 9 workload images exist in both; all 9 have the same digest (tag resolved
  with crane) and the same SBOM state (6 with SBOM, 3 without).
- **v13s's `testapp:latest` is stale.** debug, tommy/debug and johnny run
  `testapp@sha256:2534669d…` (Alpine 3.24.3, libssh2 1.11.1-r4). v13s reports
  580 findings (35 critical, 250 high) for `testapp:latest` from an older SBOM
  (Alpine 3.22.2, libssh2 1.11.1-r0); for the same digest under its immutable tag
  v13s reports 0, and so does v0s. Image identity by name:tag goes stale with
  mutable tags; by digest it does not.
- On the other images every v13s-only finding is a duplicate of one v0s has,
  under another ID: GHSA alias (tokendings/guava), GO-IDs aliased to the CVE, and
  Echo vendor advisories (`ECHO-…`, upstream = the CVE) attached to ordinary Go
  purls. kafka-canary: 3 distinct vulnerabilities in v0s, 7 rows in v13s.
- v0s-only findings are all unfixed (tokendings 66: 4 high, 39 medium, 20 low,
  3 unknown) — hidden by DT's `ignore_unfixed`, shown by v0s by decision.
- Workloads only in v13s: two Naisjobs without Pods (one yearly, one never run).
  Only in v0s: 32 platform workloads, almost all without attestations.

## Open

- `owner_kind` is ReplicaSet, not Deployment.
- compare.py does not normalise Docker Hub names (`deviceinsight/kafkactl` vs
  `docker.io/deviceinsight/kafkactl`).
- dev-nais has few images with SBOMs (11); nav is needed for volume.
- Not yet exercised: DB update rescan, two replicas, restarts, suppressions,
  new deploy → findings latency.
