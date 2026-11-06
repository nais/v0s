const R = "/Users/hrv/ws/sessions/v13s-veien-videre/v0s-review-1";
const common = `
You fix review findings in one lane of nais/v0s, a new Go service. The repo is your cwd: a git worktree of /Users/hrv/ws/github.com/nais/v0s, branched from main.

First read README.md, CONTEXT.md, docs/adr/0001-core-decisions.md, v0s.go and the review findings named below. Then read /Users/hrv/.pi/agent/skills/go-dev/SKILL.md and follow it. Read the code each finding points to, and confirm the finding is real before you fix it. If one is wrong, say why and skip it.

Hard rules:
- Fix the root cause minimally. No new abstractions, knobs or packages.
- For each security or correctness fix, add or adjust one behavioral regression test that would have failed before the fix. Do not over-test.
- Stay within your edit boundary. If a fix needs a change outside it, describe the change under "Contract issues" instead.
- The migration internal/database/migrations/0001_schema.sql is unreleased, so edit it in place. Only lane "data" may change it.
- Validation gate. Every command must exit 0; check the real exit codes, do not pipe:
  - gofmt -l . (must print nothing)
  - go build ./...
  - go vet ./...
  - go tool staticcheck ./...
  - V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin go test -race -count=1 ./...
  - If the proto changes: make generate, and also buf lint.
- When the gate passes, make one commit on your worktree branch.

Final report, concise:
- For each finding: fixed, skipped (and why), or contract issue.
- Notable decisions.
- Gate results.
`;

const data = `
LANE data. Edit boundary: internal/database/{workloads,images,scans,enrich,lock,database}.go and their tests, internal/database/databasetest, internal/database/migrations/0001_schema.sql, internal/reconcile, cmd/v0s.
Findings: ${R}/data.md (all), plus idiom.md items "Unnecessary staging tables", "Two image-row decoders", "Duplicate test SQL plumbing", "Postgres startup failures silently skip", "unsynced-cluster assertion", and idiom.md #4 (also data.md #1).

Decisions:
- Scan failures (data.md #1): keep scanned_db_version meaning "the version that produced the current findings". Record a failure in separate column(s), for example scan_error plus scan_failed_db_version. ClaimScans must not reclaim an image whose failure was recorded for the current version. A later successful scan clears the error. The reconcile loop records the version that the scan attempt actually used. The new scan contract, implemented by another lane: Scanner.Scan returns the DB version it used even when err != nil (zero if no DB was loaded). Do not record a failure for a zero version.
- data.md #2: make StoreSBOM write-once.
- data.md #3: use a transaction-scoped advisory lock per cluster.
- data.md #4: add a db_version column to vulnerabilities and upsert only when the incoming version is equal or newer.
- data.md #5 and #8: claim one scan at a time, and load the SBOM only for that claim. Add a sane decompressed-size limit (256 MiB) in gunzip.
- data.md #6: bound GracefulStop, then call Stop. data.md #7: put a short timeout on unlock.
- data.md #9: run the protected work on the dedicated lock connection if that is simple. Otherwise document a minimum pool size and reject smaller pools in Open.
- Remove the duplicate image-row decoder by keeping one. Remove the enrich staging tables. Simplify the test plumbing as suggested, but KEEP TestOpenMigrates. In databasetest, fail instead of skipping when the binaries exist but startup fails.
- Strengthen the reconcile test as suggested: a seeded prod workload must survive an unsynced pass.
`;

const api = `
LANE api. Edit boundary: internal/database/{findings,components,workloads_read,suppressions}.go and their tests, internal/grpcapi, internal/auth, proto/v0s/v1, api/v0s/v1 (generated; regenerate with make generate), cmd/v0s/main.go ONLY to add a panic-recovery interceptor.
Findings: ${R}/api.md (all).

Decisions:
- #1: in internal/auth, reject tokens whose JWT header alg is not RS256 before calling the validator. Google service-account ID tokens are RS256. Also add a minimal recovery unary interceptor in internal/grpcapi or internal/auth. It logs the panic and returns codes.Internal. Wire it first in cmd/v0s/main.go's ChainUnaryInterceptor.
- #2: if expires_at is present, CheckValid it and require it to be in the future.
- #3: use one resolution policy everywhere, as a union of direct ID and alias matches with ambiguity rejection for mutations. Make GetVulnerability consistent with it.
- #4: bind the canonical p.ToString().
- #5: select the suppression columns in the original joined query. Remove the second query.
- #6: document in the proto that event pagination is best-effort under concurrent writes. Do not add locking.
- #7 and #8: fix the proto comments ("unrevoked").
- API cut: give ListFindingEventsRequest its own fields: only the filters the handler actually supports. Do not reuse FindingFilter.
`;

const scan = `
LANE scan. Edit boundary: internal/scan/** (including testdata), docs/adr/0001-core-decisions.md (the scan-entry sentence only), go.mod, go.sum.
Findings: ${R}/edges.md #2, #3, #4, #8, #9; idiom.md "Inventory is restricted", "Constructor changes process-global logging", and "ADR names a scan entry point".

Decisions:
- New contract: Scan returns the DB version it used even when err != nil (zero when no DB was loaded). Capture it under the read lock.
- #3, #4 and #9 together: parse the CycloneDX document once, with cyclonedx-go, which Trivy already depends on.
  - Flatten nested components, including those under metadata.component.
  - Fill a missing purl version from component.version.
  - Build the inventory (v0s.ScanResult.Components) from every component that has a valid purl, whether or not Trivy supports its type.
  - Hand Trivy the flattened, version-filled BOM for matching.
  - Add fixture cases for each.
- #2: record the digest only after a successful swap. #8: try candidates newest-first, and prune only after one opens.
- Logging: remove slog.SetDefault from New. First check how Trivy logs: does it use slog.Default, and does anything buffer messages in memory until a logger is set? If something must be set globally, expose it as an explicit package function that main calls. Document it in the report so the integrator can wire it.
`;

const edge = `
LANE edge. Edit boundary: internal/attest, internal/kube, internal/enrich (all including tests and testdata), README.md, CONTEXT.md.
Findings: ${R}/edges.md #1, #5, #6, #7; idiom.md #1 (completed pods).

Decisions:
- #1 is critical: set ClaimVerifier to cosign.IntotoSubjectClaimVerifier for both verification paths. Add a regression test that is as close to real as feasible. If a full signed fixture is infeasible, test that the CheckOpts you build carry the claim verifier, and explain why.
- #5: skip runtime IDs that are bare sha256 values, or docker:// values without a repository, as unresolved, with a debug log. Do not resolve tags.
- #6: include init-container statuses that are currently running (native sidecars).
- #7: reject entries with empty or malformed CVE IDs, a KEV count that does not match the parsed entries, and EPSS values that are non-finite or outside [0,1].
- Completed pods: DO NOT exclude them. Including Succeeded and Failed Job pods that are still present is deliberate. It makes the images of naisjobs and cron jobs stay visible between runs. Instead, fix README and CONTEXT so they say "images in pods present in the cluster, including completed job pods", rather than "running".
`;

const tasks = [
  { key: "data", label: "Fix data/concurrency findings", agent: "worker", task: common + data, worktree: true },
  { key: "api", label: "Fix API/security findings", agent: "worker", task: common + api, worktree: true },
  { key: "scan", label: "Fix scanner findings", agent: "worker", task: common + scan, worktree: true },
  { key: "edge", label: "Fix attest/kube/enrich findings", agent: "worker", task: common + edge, worktree: true },
];
