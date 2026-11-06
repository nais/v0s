## Review — round 2: security and input handling

I reviewed the current HEAD (`4472e96`) in these files: `internal/{auth,grpcapi,attest,scan,kube,enrich}`, plus the database code touched by the API fixes (`findings.go`, `suppressions.go`, `components.go`, `enrich.go`, `scans.go`). I also checked the pinned upstream code: idtoken v0.310.0, cosign v3.1.4, trivy v0.76.1 and packageurl-go v0.1.7.

Two limits on this review:
- **No diff was reviewed.** `watchdog_diff` can't show committed ranges, so I couldn't inspect `57fde15..HEAD` itself. I reviewed the resulting source instead.
- **No tests were run.** I have no shell tool. You still need to run: `V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin go test -race -count=1 ./...`

### Round-1 fixes verified as correct
- **RS256 pre-check (`auth.go:52-55`, `73-87`): correct.** I tried to find a header that our check reads as RS256 but the validator reads differently, and found none:
  - `tokenAlgorithm` decodes the same first segment as `idtoken` does, with the same decoder (`base64.RawURLEncoding`) and the same JSON rules (`encoding/json`, `json:"alg"`).
  - Case-folded keys and duplicate keys resolve identically in both: case-insensitive matching, last key wins.
  - Our parser is less strict than idtoken's `jwtHeader`, and any parse failure returns `""`, which is rejected.
  - `TestUnaryInterceptorRejectsES256` drives the real validator through a controlled set of signing keys.
- **Recovery interceptor: correct.** It is the outermost interceptor (`main.go:137-140`), so it also catches panics inside auth. Every RPC is unary.
- **Expiry validation: correct.** The handler runs `CheckValid()` and requires the expiry to be in the future whenever `expires_at` is present (`grpcapi/suppressions.go:30-38`). The database re-checks it.
- **Alias resolution: correct.** `vulnerabilityIDs` (`findings.go:461`) takes the union of direct-ID and alias matches, which is the same matching `vulnerabilityMatch` uses. `CreateSuppressions` and `GetVulnerability` both reject names that match more than one vulnerability.
- **Purl canonicalization: correct.** `packageMatch` binds `p.ToString()`. That is idempotent with how stored component and finding purls are built: qualifiers are sorted and keys lower-cased.
- **Joined suppression query: correct.** The suppression is now read in the same statement that filters on it (`LEFT JOIN … suppressionJoin`, `findings.go:270`). The partial unique index `suppressions_one_unrevoked` allows at most one active row, so the join can't duplicate findings.
- **`ClaimVerifier` on both cosign paths: correct.**
  - Legacy path: `verifyInternal` calls `IntotoSubjectClaimVerifier` with the resolved digest (verify.go:932). The new test proves that a validly signed attestation for image A is rejected for image B.
  - Bundle path: it was already bound by `WithArtifactDigest(hash)`, where `hash` comes from `ResolveDigest` of the requested digest reference (verify.go:1751-1760, 1956). It now also runs `ClaimVerifier` (1994).
  - `Annotations` is nil, so `correctAnnotations` is a no-op.
- **Bare image IDs: correct.** `parseImageID` requires `repo@sha256:<non-empty>` and rejects bare and `docker://sha256:` IDs.
- **Native sidecars: fixed.** Running init-container statuses are now included and kept by `stripPod`. One gap remains (Finding 2).
- **Feed validation: correct.**
  - Every entry needs a valid CVE ID.
  - EPSS score and percentile must be in [0,1], and NaN is rejected.
  - The KEV `count` must equal the number of entries.
  - Duplicate CVEs fail the COPY, the transaction rolls back, and the stored data is kept.
- **CycloneDX flatten: correct, including against hostile input.**
  - Cycles are impossible in a JSON tree.
  - Depth is bounded by `encoding/json`'s nesting limit.
  - Duplicate purls are deduplicated in `result()` and `insertComponents`. Duplicate bom-refs only collapse Trivy's relationship map; nothing crashes.
  - When a purl's version and the component's `version` disagree, the purl wins, consistently for both the inventory and Trivy.
- **DB install retry and prune ordering: correct.** `s.digest` is now set only after a successful swap or a deliberate "not newer" decision. `New` opens candidates newest-first and removes older ones only after one opens.

### Findings

**Finding 1 — low: filling the purl version bypasses purl normalization and validation**
- **Location:** `internal/scan/scan.go:179` (`p.Version = c.Version`), with the consequence at `:186-193` and `:117/:130`.
- **Cause:** the version is set on an already-parsed purl, so packageurl-go's `Normalize`/`validCustomRules` never run on it. `component()` then re-parses the purl through `purl.PackageKey`.
- **Scenario 1:** a component has `purl: "pkg:chrome-extension/<32 letters>"` and `version: "latest"`. `PackageKey` fails ("chrome-extension version must be…"), `decode` returns an error, and the whole image scan fails because of one exotic component. Before this change, Trivy just skipped that component.
- **Scenario 2:** a `pkg:huggingface` component with an upper-case `version` is stored un-lowercased. The canonical query from `packageMatch` and the finding purl Trivy produces are lower-cased, so exact lookups miss it.
- **Minimal fix:** in `fillPURL`, after setting the version, re-parse with `packageurl.FromString(p.ToString())`. If that fails, keep the original versionless purl; otherwise use the normalized result.

**Finding 2 — low: a native sidecar that isn't currently running drops out of the inventory**
- **Location:** `internal/kube/kube.go:140` and `:192`.
- **Cause:** init statuses are included only when `State.Running != nil`. Regular containers are included in any state.
- **Scenario:** a native proxy sidecar goes into CrashLoopBackOff, so its state is Waiting. On the next sync it disappears from `workload_images`, and its image's findings vanish from every "in use" query until it runs again. A crashlooping main container stays visible.
- **Minimal fix:** in `stripPod`, keep the set of init-container names whose `spec.initContainers[].restartPolicy == Always`. Include those statuses in any state, plus any other init container that is currently running.

**Finding 3 — low, only matters if any deployment already holds scanned data: the inventory fixes don't reach images that were already scanned**
- **Location:** `internal/database/scans.go:287-294`.
- **Cause:** `insertComponents` does nothing if the image already has any component rows. Rows from the old Trivy-only inventory are never replaced on rescan.
- **Effect:** for those images, nested components, `pkg:generic` and other unscannable purls, and versionless purls stay missing or wrong. For example, the old row is `pkg:npm/lodash` with an empty version, while the new finding purl is `…@4.17.20`. Findings themselves are refreshed. The repo has only `0001_schema.sql` and no deployment manifests, so this may well be moot.
- **Minimal fix:** replace the image's components on every `StoreScan` (DELETE, then COPY in the same transaction), or ship a migration that truncates `components`.

### Note (not a finding; existed before these fixes)
`githubIdentity` matches only the certificate SAN. For GitHub Actions, the SAN is the *reusable workflow's* path, so a repo outside the trusted orgs that calls a public reusable workflow in `nais`/`navikt` gets a certificate that matches. This becomes exploitable only if such a workflow signs attestations from caller-supplied inputs, and I couldn't check that. To harden it, also check the source-repository-owner extension in the certificate.

### Merge verdict: OK with notes
No blockers. All the round-1 security and input-handling fixes listed above are correct. Findings 1–3 are low severity.