## Review

Read all five required documents first, then the named database paths, gRPC handlers, authentication code, relevant tests, and the pinned Google token validator. No files changed.

### Findings

#### 1. P1 / high — An unauthenticated malformed token can crash the process

**Location:** `internal/auth/auth.go:48`; `cmd/v0s/main.go:137`. Root cause in pinned dependency `google.golang.org/api@v0.310.0/idtoken/validate.go:232`.

**Scenario:** Send any RPC a JWT containing:

- `alg: ES256`;
- a current, publicly available Google IAP key ID;
- the configured audience and a future expiry;
- an empty or sufficiently short signature.

The validator reaches `sig[:32]` without checking the signature length and panics. The request does not need a valid signature or an allowed email. The server installs no panic-recovery interceptor, so the panic terminates the process.

**Evidence:** The production interceptor calls `idtoken.Validate` directly. Its ES256 implementation checks the key ID, then slices the attacker-controlled decoded signature unconditionally.

**Minimal fix:** Use a validator version with proper signature-length validation. A narrow interim fix is to reject ES256 before validation—the intended service-account ID tokens use RS256. Add a regression test using the real validator and controlled JWKS transport, not only the current fake validator.

---

#### 2. P1 / medium — A supplied past expiry can become “never expires”

**Location:** `internal/grpcapi/suppressions.go:27–28`; `internal/database/suppressions.go:104`, `:221–224`.

**Scenario:** Create a suppression with the valid protobuf timestamp `0001-01-01T00:00:00Z`, represented by seconds `-62135596800`.

`AsTime()` converts this to Go’s zero `time.Time`. Database validation skips zero times, and insertion converts the zero value to SQL `NULL`. An explicitly supplied expiry in the distant past therefore creates a permanent suppression.

**Evidence:** The handler loses timestamp presence during conversion. Both future-expiry validation and SQL nullability use `IsZero()` as the “expiry omitted” sentinel. The handler also never calls `Timestamp.CheckValid()`.

**Minimal fix:** When `expires_at` is present, validate the protobuf timestamp and require the converted value to be in the future before passing it to the database. Preserve absence separately if the database API is subsequently changed.

---

#### 3. P1 / medium — Read filters and suppression creation disagree about alias resolution

**Location:** `internal/database/findings.go:103–105`, `:460–466`; `internal/database/suppressions.go:141–155`.

**Scenario:** Initially Trivy reports a GHSA-only vulnerability `G`. Later it reports CVE `C` with alias `G`. The old vulnerability record `G` remains; scan storage does not delete it.

- `ListFindings(vulnerability_id=G)` matches current findings for `C`, because `vulnerabilityMatch` matches direct IDs **or** aliases.
- `CreateSuppressions(vulnerability_id=G)` resolves only the old direct record `G`, because `vulnerabilityIDs` suppresses alias resolution whenever a direct record exists.
- Creation succeeds but does not suppress the current CVE findings shown by the same filter.

`GetVulnerability` has the same precedence mismatch.

**Evidence:** The filter uses an unconditional OR; the resolver uses `NOT EXISTS (SELECT 1 FROM vulnerabilities WHERE id = $1)`. The schema permits an identifier to be both a direct ID and an alias.

**Minimal fix:** Use one resolution policy. For the proto’s “must resolve to exactly one” mutation contract, union distinct direct and alias matches and apply the existing ambiguity rejection instead of silently choosing the stale direct record.

---

#### 4. P1 / medium — Valid equivalent versioned purls silently miss findings and components

**Location:** `internal/database/findings.go:110–116`; affects `ListFindings`, `CountFindings`, and `SearchComponents`.

**Scenario:** An image contains canonical purl:

`pkg:npm/%40scope/name@1.2.3`

Query using the valid equivalent spelling:

`pkg:npm/@scope/name@1.2.3`

The parser accepts and normalizes it, but the versioned branch binds the **original input string**, so SQL equality returns no match. Equivalent percent encodings, case normalization for applicable package types, and qualifier ordering have the same problem.

**Evidence:** Scan storage uses the parsed purl’s canonical string (`internal/scan/scan.go:144`, `:168`). Package-key matching canonicalizes; versioned matching instead calls `args.add(pkg)`. `internal/purl/purl_test.go` already recognizes the scoped-NPM spellings as equivalent.

**Minimal fix:** Bind `p.ToString()` in the versioned branch. Test canonical-equivalent versioned inputs through both finding and component APIs.

---

#### 5. P1 / medium — A finding can carry a revoked “active” suppression

**Location:** `internal/database/findings.go:266`, `:303–305`, `:323–339`; contract at `proto/v0s/v1/v0s.proto:149`.

**Scenario:**

1. `ListFindings(suppressed=ONLY)` selects an active suppression’s ID.
2. Another request revokes or replaces that suppression.
3. The listing’s second query loads the now-revoked row.

The response contains a supposedly suppressed finding whose attached suppression has `revoked_at` set. With replacement, it can also return the predecessor rather than the suppression currently covering the finding.

**Evidence:** Suppression eligibility and suppression contents are read in separate autocommit statements. The second query filters only by ID.

**Minimal fix:** Select the full suppression in the original joined query, or use one repeatable-read transaction for both reads. Merely rechecking activity in the second query would still leave inconsistent filtering.

---

#### 6. P2 / medium — Concurrent commits can leave holes in event pagination

**Location:** `internal/database/findings.go:563`, `:587`, `:602–605`; writer at `internal/database/scans.go:248–259`.

**Concrete schedule:**

1. Scan transaction A allocates event ID 1, then pauses before committing.
2. Independent scan transaction B commits event IDs 2 and 3.
3. Listing with page size 1 returns ID 2 and a cursor after 2.
4. A commits.
5. The next page applies `ev.id > 2`, returning ID 3 and omitting ID 1 from the traversal.

**Evidence:** Identity allocation is not commit-ordered. Event insertion occurs before the remaining finding/component work and transaction commit. The cursor has no snapshot or commit-order protection. Concurrent suppression creation has the same sequence-ID characteristic.

**Minimal fix:** If history pagination must not omit concurrent committed records, serialize event-ID allocation with a transaction-scoped lock held through commit, or implement snapshot-backed pagination. Otherwise explicitly document the weaker consistency; the current tests exercise only unchanged datasets.

---

#### 7. P2 / low — The proto hides a change in the counting unit

**Location:** `internal/database/findings.go:397–400`, `:425–434`; `proto/v0s/v1/v0s.proto:16`.

**Scenario:** One image has two findings and runs in two workloads in one namespace. Listing that namespace returns two findings; grouping its count by namespace returns four.

**Evidence:** Namespace counting deliberately retains `wi.workload` in the distinct projection. `internal/database/findings_test.go:183–184` explicitly expects this multiplication. Thus this is intentional workload-incidence counting, not accidental container-join duplication—but the public contract only says it counts matching findings grouped by dimension.

**Minimal fix:** Copy the Go counting-unit documentation into the proto. If namespace buckets are intended to count distinct findings instead, remove workload identity from that grouping’s distinct projection.

---

#### 8. P2 / low — Revocation accepts expired suppressions despite the proto’s “active” contract

**Location:** `internal/database/suppressions.go:273–275`; `proto/v0s/v1/v0s.proto:31`.

**Scenario:** Revoke an expired but unrevoked suppression. The request succeeds and records a revocation, although the domain definition says expired suppressions are inactive and the RPC says it revokes active suppressions.

**Evidence:** The UPDATE checks only `revoked_at IS NULL`, unlike active-suppression reads, which also check expiry.

**Minimal fix:** Change the proto comment to “unrevoked suppressions” if the current, reasonable behavior is intended.

### Correct / found sound

- **SQL construction:** User-controlled values are parameterized. Dynamic column/grouping expressions come from fixed internal choices. Component prefix search escapes `%`, `_`, and backslashes.
- **Namespace handling:** Empty namespace lists intentionally mean all namespaces, consistent with the documented empty-filter semantics. Production authentication is tenant-wide service-account authorization, not per-user namespace authorization; I found no contrary namespace-access contract.
- **Unchanged-data pagination:** Finding, component, and workload cursors contain complete ordering keys; workload pagination limits workloads rather than joined container rows.
- **Counting implementation:** Global/image/severity/vulnerability counts avoid workload fan-out. Workload counts deduplicate containers correctly. Namespace multiplication is intentional and tested, as distinguished above.
- **Suppression storage:** The partial unique index prevents multiple unrevoked predecessors. Replacement and expired-predecessor revocation occur in the same transaction. Batch failure rolls back preceding mutations. Package keys drop version, qualifiers, and subpath as intended.
- **Dry run:** Suppression rows and revocations are rolled back; no persisted suppression-row leak found. PostgreSQL sequence values are still consumed.
- **Authentication/error handling:** Audience and allowlist configuration are mandatory in production. Email matching is exact, not a suffix wildcard. All currently registered RPCs are unary and covered by the interceptor. Unexpected database errors are logged and reduced to generic client errors by `toStatus` (`internal/grpcapi/grpcapi.go:43–66`).

### API shape / what to cut

The overall RPC set is reasonably small. **Cut reuse of `FindingFilter` in `ListFindingEventsRequest`** (`proto/v0s/v1/v0s.proto:272–273`). The handler uses only four fields (`internal/grpcapi/grpcapi.go:214–221`); accepting cluster, workload, package, severity, fix and suppression fields only to ignore them is an avoidable API trap. Give events their actual filters and document that namespace matching uses **current**, not historical, workload placement.

### Validation limitation

I inspected tests but could not execute commands with this session’s available tools. Requested supervisor validation:

`V0S_PG_BIN=/Users/hrv/.cache/v0s/pg18/bin go test ./internal/database ./internal/grpcapi ./internal/auth`

### Merge verdict: **BLOCK**

Fix the unauthenticated token-validation crash before exposing the service.