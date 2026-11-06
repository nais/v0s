## Review

Read-only review of the required docs/schema, targeted write paths, reconciliation loops, scanner version handoff, and shutdown. **No files changed.** Findings below are source-verified scenarios; I could not execute tests because this session has no execution tool.

### Findings

#### 1. High / P1 — Failed scans advance the successful-results version

**Location:** `internal/database/scans.go:75–78`, `internal/reconcile/reconcile.go:175–182`

`RecordScanFailure` executes:

```sql
SET scan_error = $3, scanned_db_version = $2, scan_lease_until = NULL
```

It does not replace the existing findings. Thus:

1. An image has findings from DB v1.
2. Scanning with v2 fails.
3. The image now reports `scanned_db_version = v2`, but its findings still come from v1.
4. `ClaimScans` excludes it for v2. A concurrent successful v2 worker is also discarded by `StoreScan`’s version guard at `scans.go:108–109`.

This contradicts the schema’s “current findings … according to scanned_db_version” contract (`0001_schema.sql:87`).

Additionally, the error path rereads `Scanner.DBVersion()`. A swap between the failed scan and that read can mark an entirely unattempted newer DB version as failed/completed.

**Minimal fix:** Separate attempted/failed scan bookkeeping from the last successful `scanned_db_version`. Preserve successful-result provenance, use retry backoff, and propagate the actual attempted version rather than rereading the current version after an error.

#### 2. High / P1 — A late fetch can overwrite an SBOM after its findings and inventory were stored

**Location:** `internal/database/images.go:77–91`; `internal/database/scans.go:268–276`

`StoreSBOM` unconditionally updates the image and overwrites an existing document:

```sql
ON CONFLICT (image_id) DO UPDATE SET document = excluded.document
```

**Failure scenario:** Replica A’s fetch exceeds its five-minute lease. Replica B fetches a different valid attestation for the same image, stores it, and scans it. A subsequently completes and overwrites B’s SBOM. The stored findings still describe B’s document, while future scans read A’s document. Components remain from B indefinitely because `insertComponents` returns immediately once any components exist.

An image digest is immutable; its set of attached attestations is not. The fetcher selects the first matching statement (`internal/attest/attest.go:133–151`).

**Minimal fix:** Make successful SBOM storage write-once. Under the image-row lock, treat an already-fetched image as a no-op and do not replace its document.

#### 3. Medium / P1 — Concurrent snapshots can produce a union that neither replica observed

**Location:** `internal/database/workloads.go:30–54`

The transaction locks individual images but never serializes replacement of a particular cluster’s snapshot.

**Failure scenario:** Two replicas have disjoint snapshots `{X}` and `{Y}` for the same initially empty cluster:

1. Both upsert their different images, acquiring no conflicting image locks.
2. Both execute `DELETE ... WHERE cluster = $1` before either inserts workload rows.
3. Both insert and commit.

The final cluster contains `{X,Y}`, violating the method’s “complete set” contract. An existing snapshot also permits this outcome when one deletion waits for another transaction: its statement snapshot does not include the other transaction’s subsequently inserted rows.

**Minimal fix:** Acquire a transaction-scoped, cluster-specific advisory lock before the image upserts and snapshot replacement. Keep the existing image ordering for cross-cluster safety.

#### 4. Medium / P1 — Older replicas can roll shared vulnerability metadata backward

**Location:** `internal/database/scans.go:112`, `136–183`

The per-image version guard does not protect the globally shared `vulnerabilities` rows. Their upsert receives no DB version and overwrites all metadata whenever values differ.

**Failure scenario:**

1. Replica A stores image A using DB v2, updating a CVE’s title/CVSS.
2. A lagging replica stores previously unscanned image B using DB v1.
3. B’s accepted scan overwrites that CVE with v1 metadata.

Image A still reports v2, but `ListFindings` joins its title and CVSS from the downgraded shared row (`internal/database/findings.go:254–263`).

**Minimal fix:** Store the metadata’s source DB version and only replace shared metadata with an equal/newer version. Pass `dbVersion` into the vulnerability upsert.

#### 5. Medium / P1 — Sequential batches outlive their leases even when individual scans are reasonably short

**Location:** `internal/reconcile/reconcile.go:29–30`, `162–167`; `internal/database/scans.go:27`

All sixteen jobs receive a five-minute lease simultaneously, then run **sequentially**, without renewal or a per-job deadline.

**Failure scenario:** At 25 seconds per scan, the batch takes about 400 seconds. After 300 seconds, another replica can claim remaining/in-progress jobs while the original worker continues processing them. This duplicates expensive work without any individual scan exceeding five minutes.

Successful `StoreScan` calls are idempotent, so this alone does not duplicate finding events. However, the failure bookkeeping described in finding 1 can discard a successful overlapping result.

**Minimal fix:** For the current serial scanner, claim one job at a time. Renew leases or enforce appropriate deadlines for individual scans that can themselves exceed the lease.

#### 6. Medium / P1 — Shutdown can block indefinitely in `GracefulStop`

**Location:** `cmd/v0s/main.go:173–177`

The ten-second timeout is created **after** synchronous `srv.GracefulStop()`, so it does not bound gRPC shutdown. RPCs use their request contexts, not the canceled service context.

**Failure scenario:** A client without a deadline calls `ListFindings` while another PostgreSQL session holds an exclusive lock on `findings`. SIGTERM cancels the reconciliation loops, but not that RPC’s database query. `GracefulStop` waits indefinitely; probe shutdown and the remaining joins are never reached.

**Minimal fix:** Start graceful stopping asynchronously, wait for a bounded grace period, then call `srv.Stop()` to cancel outstanding RPCs.

#### 7. Medium / P1 — Advisory-lock cleanup removes cancellation without adding a deadline

**Location:** `internal/database/lock.go:28–32`

Cleanup uses:

```go
ctx := context.WithoutCancel(ctx)
conn.Exec(ctx, `SELECT pg_advisory_unlock(...)`, ...)
```

**Failure scenario:** The dedicated PostgreSQL backend becomes unresponsive before unlock. Even after service cancellation and callback completion, unlock has neither cancellation nor a deadline. The deferred connection release never runs, the reconciliation wait group cannot finish, and main remains waiting for its completion.

The existing close-on-unlock-error safeguard does not help until `Exec` returns.

**Minimal fix:** Put a short timeout around cancellation-independent cleanup. On failure, close/discard the connection as already intended.

#### 8. Medium / P2 — Scan claims eagerly retain an entire batch of decompressed SBOMs

**Location:** `internal/database/scans.go:45–55`, `63–69`; `internal/reconcile/reconcile.go:162–167`

`ClaimScans` calls `gunzip` for every row and collects all decompressed documents before processing any. `gunzip` uses `io.ReadAll` without a local size limit.

**Failure scenario:** Sixteen valid 64 MiB SBOMs require **1 GiB of retained document bytes alone**, before Trivy’s parsed structures and allocation overhead. With a 512 MiB process budget, claiming the batch cannot complete. Subsequent attempts encounter the same batch.

The pinned cosign dependency does cap normal attachments at 128 MiB, so I am **not** claiming an unlimited registry decompression bomb. That cap nevertheless permits this batch amplification.

**Minimal fix:** Claim metadata and load/decompress documents only when a worker can process them, or claim one job for the current serial loop. Enforce an explicit decompressed-document limit as well.

#### 9. Medium / P2 — Singleton jobs deadlock with an accepted small pool configuration

**Location:** `internal/database/lock.go:15–19`, `36`; `internal/reconcile/reconcile.go:201–206`, `219–220`; `internal/database/database.go:28–29`

`WithLock` retains one pool connection while its callback performs database operations through the same pool.

**Failure scenario:** With the valid DSN option `pool_max_conns=1`, GC acquires the only connection and then waits forever inside `DeleteUnusedImages` for another connection. All other database work also waits. With two connections, enrichment and GC can each retain one and both wait for their callbacks’ database operations.

The normal default pool is larger; this finding is configuration-dependent.

**Minimal fix:** Execute protected SQL using the dedicated connection, or explicitly reject pool configurations too small for the retained singleton connections plus callback work.

### Correct: checked and found sound

- **Successful scan version handoff:** `internal/scan/scan.go:67–80` holds the read lock through matching and returning the version actually used. The success path stores that returned version, rather than the earlier claim version.
- **Finding-event differences and `first_seen_at`:** `internal/database/scans.go:103–115`, `203–264` lock the image, deduplicate finding keys, preserve timestamps for persistent findings, and write events/findings atomically. Same/older successful results are ignored. Existing tests explicitly cover those cases (`scans_test.go:63–150`).
- **Claims within a live lease:** The claim statements atomically update leases using `FOR UPDATE SKIP LOCKED`; concurrent SBOM claims have a dedicated test (`images_test.go:58`).
- **Enrichment replacement atomicity:** Temporary-table COPY, deletion, and insertion share one transaction (`internal/database/enrich.go:42–56`). Duplicate-input rollback protection is tested (`enrich_test.go:35–38`). EPSS does retain the full feed plus boxed COPY rows, but I have not established an additional concrete memory failure at approximately 300k rows.
- **GC’s normal path:** It requires both an old `last_seen_at` and no workload reference (`internal/database/images.go:121–123`), with timestamps refreshed in the snapshot transaction. I found no evidenced normal-path deletion of an in-use image.
- **Goroutine accounting:** Fetch batches join their workers; reconciliation joins its loops; main’s error channel accommodates its four producers. The shutdown problems above are blocking waits, not an independently evidenced missing join.

### Verification limitation

Tests were inspected but **not run**. Recommended baseline:

```sh
V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin \
  go test ./internal/database ./internal/reconcile ./internal/scan ./cmd/v0s
```

**Fixed:** None — read-only review.  
**Merge verdict: BLOCK** pending correction of the result-version and SBOM consistency defects.