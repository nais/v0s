I could not run the test suite: this session has no command-execution tool. Run `V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin go test -race -count=1 ./...` before merging. Everything below comes from reading the source at HEAD `4472e96`. `watchdog_diff` only shows uncommitted changes and there are none, so I reviewed the resulting code and tests rather than the commit diff itself.

## Review

### Round-1 fixes I verified as correct
1. **Scan failure recording and claiming (#1, #5).**
   - `RecordScanFailure` (`scans.go:84-95`) now writes only `scan_error`, `scan_failed_db_version` and the lease. Findings and `scanned_db_version` are left alone. Its guard skips images already scanned with that DB version or newer, or already failed with a newer one.
   - The failure is recorded under the version the scan actually used, not a fresh `DBVersion()` read (`scan.go:63-67`, `reconcile.go:173-191`).
   - I traced the races between two replicas whose leases overlap. Success then failure: the failure is a no-op. Failure then success: `StoreScan` clears the failure (`scans.go:134-138`). Both orders end in the right state.
   - `ClaimScan` takes one image at a time (`reconcile.go:159-171`), which removes the "16 jobs on one lease" problem.
   - `TestRecordScanFailure` and `TestScanFailureRecordsUsedVersion` test the right behaviour.
2. **`StoreSBOM` write-once (#2).** `images.go:66-86` locks the image row with `FOR UPDATE`. Under read-committed isolation, a second writer waits, then sees `fetched` and does nothing. Nothing ever moves `sbom_state` back from `fetched`; `RecordSBOMFailure` is guarded at `images.go:98`. So the plain `INSERT INTO sboms` cannot hit a conflict. `TestStoreSBOMKeepsFirst` only covers the two writes one after another, but the locking logic is simple enough to trust.
3. **Per-cluster advisory lock (#3).** `workloads.go:35-40` takes the lock before any row locks. Each later statement starts its own snapshot, so the `DELETE` sees rows the previous holder committed. Only this code takes the lock and it always takes it first, so it cannot form a deadlock with the sorted image locks. The two-key lock spaces do not overlap the migration lock. `TestSyncWorkloadImagesConcurrently` (using a sleep trigger) would fail without the lock.
4. **`vulnerabilities.db_version` guard (#4).** In `scans.go:177-194`, a NULL or older stored version gets replaced, an equal version is updated only if the data differs, and a newer one is kept. The new value (`$9`) is never NULL. `TestStoreScanKeepsNewerVulnerability` covers it.
5. **Dedicated lock connection outside the pool (#7, #9).**
   - `lock.go:22-41` opens a separate connection, and the deferred close is limited by a 5-second timeout.
   - `pgconn.Close` closes the socket even if the clean shutdown fails, so the connection is neither leaked nor left hanging.
   - `pool_*` settings are removed by `pgxpool.ParseConfig`, so `ConnConfig.Copy()` is a clean copy.
   - `TestWithLockSinglePoolConnection` demonstrates the old deadlock with `pool_max_conns=1`.
6. **`stopGRPC` (#6).** `main.go:207-220` waits 10 seconds for a graceful stop and then calls `Stop()`. `Stop` closes connections without waiting for handlers by default, so `<-stopped` returns. `TestStopGRPCCancelsHangingRPC` checks this.
7. **Gunzip cap (#8).** In `scans.go:64-77`, reading through `LimitReader(max+1)` and then checking `> max` is correct. Only one decompressed SBOM is held per claim now.
8. **Migration.** The new columns were added by editing `0001_schema.sql` in place. That is safe only because nothing has been deployed yet: the git log shows the whole history was written today. Any database that already ran the old version 1 would never get `scan_failed_db_version` or `db_version`, and `ClaimScan` would fail on the missing column. Once anything is deployed, schema changes must go in a new `0002_*.sql`.

### Findings

- **Finding: Low. Failures outside `Scanner.Scan` are never recorded, so the image is retried forever.**
  - **Where:** `scans.go:58-61` (gunzip error after the lease UPDATE has already committed) and `reconcile.go:186-188` (a `StoreScan` error is only logged).
  - **Scenario:** An SBOM component has a name containing `\u0000`. JSON decoding accepts it, `decode` puts it in `v0s.Component.Name` (`scan.go:157-159`), and Postgres rejects 0x00 in `text` during the `components` COPY. `StoreScan` rolls back, and `scan_error` and `scan_failed_db_version` stay empty.
  - **Effect:** The image shows no findings and no error. Every 5 minutes, after the lease expires, some replica claims it and scans it again in full. A corrupt or oversized gzip document follows the same endless cycle through `ClaimScan`.
  - **Smallest fix:**
    - When decompression fails inside `ClaimScan`, mark a failure for `dbVersion` and clear the lease. Use the same UPDATE as `RecordScanFailure`, then claim the next image.
    - In `scanOne`, call `RecordScanFailure` when `StoreScan` fails with a permanent error, i.e. a `*pgconn.PgError` of class 22 or 23 (data exception or constraint violation), and not on connection or context errors.
    - Alternatively, strip NUL bytes from strings in `scan.result`.

- **Finding: Low (left over, not caused by the fixes). Nothing stops a scan from outrunning its lease or crashing the process.**
  - **Where:** `reconcile.go:29` (`lease`), `reconcile.go:174-175`. Leases are never renewed and there is no deadline per scan.
  - **Scenario:** One SBOM costs more memory in Trivy than the pod's limit allows. Because the 256 MiB decompression cap is above what a normal attestation can be, it does not prevent this. The replica gets OOM-killed before it can record a failure. After 5 minutes the lease expires and the next replica claims the same image; `NULLS FIRST` puts unscanned images first. Every replica then restarts about every 5 minutes, and the gRPC API goes down with them. A scan that takes longer than 5 minutes without crashing is likewise repeated on every replica.
  - **Smallest fix:** Count claims per image in `ClaimScan` with a `scan_attempts` column. Reset it in `StoreScan` and when the DB version changes. After N claims (e.g. 3) without a result, record a failure for that `dbVersion`.

No other issues found. In particular, I found none of the following:
- races between replicas in the claim, store or failure paths;
- NULL-handling errors in the new guards;
- deadlocks introduced by the cluster lock;
- leaks or unbounded hangs on the lock connection.

**Merge verdict: OK with notes.** All nine round-1 data findings are fixed correctly. Both remaining issues are low-severity robustness gaps, and neither comes from the fixes themselves.