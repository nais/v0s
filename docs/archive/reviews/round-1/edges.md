## Review

Read-only review of the current checkout, including the requested docs, implementation, tests, and cached upstream sources. No files changed. Findings below are source-proven; I could not execute commands with the available tools.

Upstream paths below are relative to `/Users/hrv/go/pkg/mod/`.

### Findings

#### 1. High (P1): Legacy attestation verification does not bind the SBOM to the requested image

**Location:** `internal/attest/attest.go:98–114`

`CheckOpts` omits `ClaimVerifier`. In cosign’s legacy verification path, image-subject verification happens **only** when that callback is non-nil:

- `github.com/sigstore/cosign/v3@v3.1.4/pkg/cosign/verify.go:932–936`
- `pkg/cosign/verify.go:306–329` verifies the DSSE signature, not the image subject.

**Scenario:** A registry writer copies a legitimately signed, clean SBOM attestation for digest A—including its certificate and Rekor bundle—to digest B’s legacy `.att` tag. The trusted organization’s signature still verifies, and v0s returns A’s predicate as B’s SBOM. The attacker need not possess the trusted signing identity.

The modern bundle path separately enforces `WithArtifactDigest`; the fallback loses that protection.

**Minimal fix:** Set `ClaimVerifier: cosign.IntotoSubjectClaimVerifier` before either verification attempt. Add a regression test with a valid signature whose statement names a different digest.

#### 2. Medium (P1): A failed DB installation is remembered as successfully handled

**Location:** `internal/scan/db.go:115–116,132–147`

`s.digest` is updated before `os.Rename` and `s.swap` succeed. After either operation fails, the next update sees the same digest and immediately returns success-without-update.

**Scenario:** Download and metadata validation succeed, but installation encounters a transient filesystem/open error. The previous DB remains loaded. Even after the local problem is repaired, that artifact is never retried until the registry digest changes or the process restarts. On initial installation, this can leave the service without a DB. The early success can also prevent trying subsequent repositories.

**Minimal fix:** Record the digest only after a successful swap, or after deliberately rejecting an artifact because its version is not newer. Do not retain it after installation errors.

#### 3. Medium (P1): Valid nested CycloneDX packages disappear from inventory and vulnerability matching

**Location:** `internal/scan/scan.go:91–102`

The pinned Trivy decoder does not recursively consume CycloneDX component trees:

- `github.com/aquasecurity/trivy@v0.76.1/pkg/sbom/cyclonedx/unmarshal.go:67,153–175` processes only the supplied top-level list.
- `parseComponent`, starting at line 177, never reads `c.Components`.
- CycloneDX explicitly supports nested components: `github.com/!cyclone!d!x/cyclonedx-go@v0.12.0/schema/bom-1.5.schema.json:568–570`.

**Scenario:** A valid SBOM nests a vulnerable `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` component inside an application component. Scanning succeeds, but the nested package is absent from both `Components` and `Findings`.

**Minimal fix:** Flatten nested component lists—including those below `metadata.component`—before Trivy decoding. Until supported, explicitly reject such documents rather than recording a successful incomplete scan.

#### 4. Medium (P1): Component versions are lost when the PURL omits its optional version

**Location:** `internal/scan/scan.go:91,153–157`

Trivy obtains the package version from the PURL and does not fall back to CycloneDX’s `component.version`:

- `trivy@v0.76.1/pkg/sbom/io/decode.go:200`
- `trivy@v0.76.1/pkg/purl/purl.go:235–241`
- `trivy@v0.76.1/pkg/detector/library/detect.go:30–34` skips packages with an empty version.

**Scenario:** Change the existing lodash fixture’s PURL to `pkg:npm/lodash` while retaining `"version":"4.17.20"`. This is a valid versionless PURL. v0s records an empty component version and silently skips vulnerability matching, despite the SBOM providing the vulnerable version.

**Minimal fix:** Before decoding, populate missing PURL versions from `component.version`; preserve that version in inventory. Add this variant of the existing lodash fixture as a regression test.

#### 5. Medium (P1): Bare runtime image IDs can be misreported as manifest digests

**Location:** `internal/kube/kube.go:137–145`

Every bare `sha256:…`—including one prefixed with `docker://`—is combined with `status.image` and treated as a registry manifest reference. Bare runtime IDs are not necessarily manifest digests.

Cached containerd source demonstrates the distinction:

- `github.com/containerd/containerd@v1.7.33/pkg/cri/server/image_pull.go:197–201`: image ID is the **config** digest.
- `container_create.go:209`: that ID becomes `meta.ImageRef`.
- `container_status.go:44–59`: it remains the returned image reference unless repository digests are available.

**Scenario:** A locally imported image without repository digests produces a config ID C and image name `registry/app:v1`. v0s constructs `registry/app@sha256:C`, which is not the running image’s manifest reference. Attestation lookup then queries the wrong digest.

**Minimal fix:** Treat opaque/bare runtime IDs as unresolved unless the runtime guarantees manifest-digest semantics. Accept an independently known immutable repository/manifest reference; do not resolve a mutable tag and assume it identifies the running image.

#### 6. Medium (P1): Running native sidecars are completely excluded

**Location:** `internal/kube/kube.go:107,181–185`

Both `stripPod` and `Snapshot` retain/read only `ContainerStatuses`. Kubernetes native sidecars are init containers with `restartPolicy: Always`; their statuses reside in `InitContainerStatuses`.

This behavior is documented in the pinned API source:

- `k8s.io/api@v0.37.2/core/v1/types.go:3207–3217`
- `types.go:5682`

**Scenario:** A pod runs its main application plus a long-lived native proxy sidecar. The sidecar’s image never enters `workload_images`, is never fetched or scanned, and cannot be found through inventory search.

**Minimal fix:** Include running/native-sidecar init statuses and preserve the minimal state needed by the transform. Add a running native-sidecar case; the existing test only demonstrates exclusion of ordinary init statuses.

#### 7. Medium (P1): Nonempty but invalid feeds can replace all useful enrichment data

**Location:** `internal/enrich/enrich.go:74–85,120–150`

The guards check slice length, not whether entries identify actual CVEs. Neither parser rejects an empty CVE identifier. KEV also ignores the catalog’s declared `count`.

**Concrete inputs accepted today:**

- EPSS with a valid header and the sole row `,0.1,0.2`.
- KEV:
  ```json
  {"count":1,"vulnerabilities":[{"dateAdded":"2026-10-29"}]}
  ```

Each produces one entry with `CVE == ""`, without error. The schema permits that empty primary-key value, and `internal/database/enrich.go:46–54` then deletes the old table contents and commits the invalid replacement. All existing CVE lookups consequently lose enrichment.

Likewise, a KEV response declaring thousands of records but containing one valid entry is accepted as a complete replacement.

**Minimal fix:** Reject missing/malformed CVE identifiers; validate KEV’s declared count against parsed entries. Also reject nonfinite or out-of-range EPSS scores/percentiles. Test that rejected feeds leave stored data unchanged.

#### 8. Medium (P1): Startup deletes the usable DB before opening its replacement

**Location:** `internal/scan/db.go:55–77`

Startup prunes older candidates using `readMetadata`, which only checks metadata and file existence. It opens the selected Bolt DB only after deleting the alternatives.

**Scenario:** The directory contains an older usable DB and a newer candidate with valid metadata but an unreadable/corrupt `trivy.db`—for example, left after interruption between rename and validation. Regardless of directory ordering, startup deletes the older DB, fails to open the newer one, deletes that too, and returns a scanner without a DB.

**Minimal fix:** Retain candidates until one has successfully opened. Try them newest-first, and prune alternatives only after establishing a usable DB.

#### 9. Low (P2): Scanner ecosystem support incorrectly limits package inventory

**Location:** `internal/scan/scan.go:84–102,134–159`

Inventory is built exclusively from Trivy’s scan target. Trivy drops valid PURLs whose ecosystem it cannot scan:

- `trivy@v0.76.1/pkg/sbom/io/decode.go:145–147,200–204`

**Scenario:** An SBOM contains a library identified as `pkg:generic/acme/libfoo@1.2`. Scanning succeeds, but inventory omits it entirely. That contradicts `CONTEXT.md`’s component contract: packages are stored whether or not they have findings.

**Minimal fix:** Extract inventory independently from the original CycloneDX component list. Restrict vulnerability matching—not inventory—to supported ecosystems.

### Checked and found sound

- **Identity boundary:** Organization names are regex-escaped; the GitHub host, organization boundary, and workflow directory are anchored. The issuer is the correct exact GitHub Actions issuer (`internal/attest/attest.go:61–68`). I found no organization-prefix/regexp bypass.
- **Verified-predicate selection:** `Fetch` only passes successful cosign verification results to `selectCycloneDX`; it does not merge in unverified envelopes (`attest.go:78–95`). Modern bundles explicitly verify the artifact digest upstream.
- **Trivy locking:** Within the application’s single-scanner lifecycle, `Scan` holds its read lock through matching, `FillInfo`, and result mapping; swaps hold the write lock (`internal/scan/scan.go:66–80`, `db.go:154–174`). I found no scan-versus-swap closed-DB race.
- **Normal DB update path:** Downloads use temporary directories, the same resolved OCI artifact is reused for downloading, and `UpdatedAt` comparisons prevent ordinary mirror rollback. The previous DB is reopened after a failed swap.
- **Finding fields:** Severity is taken after Trivy `FillInfo`; fixed version, status, severity source, data source, CVSS fields, and vendor IDs are mapped directly, with deterministic output sorting (`internal/scan/scan.go:127,164–264`).
- **Informer lifecycle/memory:** The transform discards specs, managed fields, and unrelated status data. Informer shutdown is awaited, resync is disabled, and unsynced caches cannot erase stored workloads (`internal/kube/kube.go:52–88,162–187`).
- **Remote Google authentication:** TLS verification remains enabled; the reusable ADC token source supplies refreshed OAuth tokens rather than a static startup token (`internal/kube/kube.go:204–229`).
- **Feed failure atomicity:** Empty feeds and ordinary parsing errors fail before replacement. Database staging/copy failures roll back the transaction rather than partially replacing live data.

### Validation / merge verdict

**Merge verdict: BLOCK**, principally because of the legacy attestation replay vulnerability.

Tests still need execution, including the corresponding negative regressions:

```text
go test -race ./internal/scan ./internal/attest ./internal/kube ./internal/enrich
go test ./internal/database
```

The database tests require the documented PostgreSQL setup.