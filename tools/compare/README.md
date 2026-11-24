# Compare v0s with v13s

`compare.py` is an exploratory tool from the first dev-nais pilot. **It targets
the old v0s API and must be updated before use.** It still assumes Google ID-token
authentication for v0s and the old image/SBOM model.

Update it to use the current protobuf contract: no v0s token, `Image.status` and
`error`, unresolved workloads, workload-level finding occurrences, and comparison
by image digest with canonical vulnerability IDs. Check registry-name normalization
as well; tag identity and raw row counts give misleading differences.

The acceptance criteria are in [Verification](../../docs/verification.md).
`compare-out/` is generated and ignored by git. Keep detailed comparison output
and workload snapshots in access-controlled storage, not in Git.
