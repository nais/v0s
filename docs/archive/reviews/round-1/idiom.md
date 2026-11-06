## Review

Read the Go skill, all three requested documents, and all non-generated Go files, excluding `api/v0s/v1`. Read-only review; tests were not run.

**Correct:** The overall design is already lean: concrete database dependency, small consumer-owned interfaces in `internal/reconcile/reconcile.go:37–53`, hand-written fakes, standard-library assertions, and no options/DI framework. Most tests exercise useful behavior; wholesale test removal is not justified.

### Findings, ranked by value

1. **Finding: P1 — Completed pods count as running workloads.**  
   `internal/kube/kube.go:107` reads container statuses without considering pod phase; `stripPod` also discards phase. `internal/kube/kube_test.go:81,111` explicitly expects a succeeded Job to remain in the inventory. This contradicts README’s “running pods” and CONTEXT’s “currently runs.” Preserve phase and exclude `Succeeded`/`Failed` pods; change that test to assert exclusion. Otherwise completed Jobs retain findings and prevent image collection.

2. **Finding: P1 — A failed DB installation suppresses subsequent retries.**  
   `internal/scan/db.go:132` records the artifact digest **before** rename/open succeeds. After either fails, the same digest hits the early return at `:115`, falsely reporting a successful no-op until the registry digest changes. Record the digest only after a successful swap, or after deliberately rejecting an older DB. Add one behavioral test: installation fails, the cause is removed, and the same artifact successfully retries.

3. **Finding: P1 — Inventory is restricted to packages Trivy understands, unlike the documented contract.**  
   `internal/scan/scan.go:84,91,135–141` derives inventory from Trivy’s decoded scan target, which drops unsupported purl types. Thus a valid SBOM component such as a generic package can disappear from package search despite CONTEXT.md:27–29 promising SBOM inventory independently of findings. Populate components from the original CycloneDX component purls; restrict only vulnerability matching to Trivy-supported packages. Add an unsupported-package inventory case to the existing scan test.

4. **Finding: P1 — Scan failure can mark an unattempted DB version as processed.**  
   `internal/reconcile/reconcile.go:175–182` calls `Scan`, then samples `DBVersion()` again on failure. If DB A produces the error and an update installs B before that sample, `RecordScanFailure` marks B processed, so B is skipped. Capture the failure version **before** calling `Scan`, conservatively, or return the attempted version alongside errors. Test an update between failure and recording.

### Concrete simplifications

All estimates below are approximate **net** lines saved.

| Finding | Location | Concrete deletion/change | Saved |
|---|---|---|---:|
| **P2 — Unnecessary staging tables** | `internal/database/enrich.go:40–54` | Within the existing transaction, `DELETE` then `CopyFrom` directly into the destination. MVCC already preserves reader visibility; rollback preserves old contents on failure. Delete temporary-table creation and staging-to-destination insertion. Existing EPSS rollback test remains useful. | ~7–10 |
| **P2 — Two image-row decoders** | `internal/database/images.go:18–36`; `internal/database/findings.go:82–96` | Delete `scanImage`; reuse `imageScan.dest()`/`image()` in both claim callbacks as the read paths already do. This removes duplicate column ordering, nullable timestamp conversion, and the extra state conversion. | ~12–15 |
| **P2 — Duplicate test SQL plumbing and redundant smoke test** | `internal/database/findings_test.go:52–72`; `internal/database/database_test.go:12–17` | Seed `newFixture` using the existing `exec` helper at `images_test.go:180`, instead of opening another connection. `TestOpenMigrates` only pings a database that every database test already opens and migrates; propose removing it while retaining `TestMain`. | ~22 |
| **P2 — Constructor changes process-global logging** | `internal/scan/db.go:34–36`; `cmd/v0s/main.go:94,115` | Delete `slog.SetDefault` from `scan.New` and its explanatory comments. Main already configures the global logger; library construction should not silently replace it. | ~4–5 |

**Total straightforward reduction: roughly 45–50 lines**, without removing required behavior or useful behavioral coverage.

### Test and documentation gaps

- **Finding: P2 — Postgres startup failures silently skip the integration suite.**  
  `internal/database/databasetest/databasetest.go:42–45` treats *every* `startCluster` error as “Postgres unavailable,” including broken installed binaries or startup failures. ADR:55–58 permits skipping when prerequisites are absent, not when setup fails. Distinguish missing prerequisites from operational errors; fail the test run for the latter.

- **Finding: P2 — The unsynced-cluster assertion cannot detect data deletion.**  
  `internal/reconcile/reconcile_test.go:75–77,101–108` starts with no stored `prod` workloads. Accidentally syncing an empty snapshot would therefore still pass. Seed an existing `prod` workload and assert it survives the unsynced pass—strengthen this test rather than adding another test scaffold.

- **Finding: P2 — ADR names a scan entry point the code does not use.**  
  `docs/adr/0001-core-decisions.md:7` says scanning calls `pkg/scan/local`; `internal/scan/scan.go:108–127` directly composes OS/language scanners and `FillInfo`. Update that sentence to describe the actual, narrower integration.

**Merge verdict: BLOCK** on the behavioral issues above; no broad architectural rewrite is warranted. Verification after fixes: `make check` with working Postgres prerequisites.