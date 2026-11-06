# Historical material

These files preserve the investigation and implementation history. They are
**not the current design, deployment instructions or an open task list**. They
may describe removed features, old APIs, resolved findings and superseded plans.
Paths, commit IDs, PR status and runtime observations are snapshots, not current
facts. Source-code paths in review notes refer to the code at review time.

For the current service, start with the [README](../../README.md),
[architecture](../architecture.md), [operations](../operations.md) and
[verification checklist](../verification.md).

## Contents

- [`background/`](background/): v13s/Dependency-Track explanations, matcher
  measurements and analysis, and an earlier suppression proposal.
- [`adr/0001-core-decisions.md`](adr/0001-core-decisions.md): the original design
  decision record, superseded by the current architecture document.
- [`reviews/`](reviews/): implementation reviews and the simplification diff.
  These are review snapshots, not a list of current defects.
- [`handover-2026-11-06.md`](handover-2026-11-06.md): session handover, pilot state
  and operational observations recorded at that time.
- [`verification-2026-11-06.md`](verification-2026-11-06.md): the earlier rollout
  proposal, including infrastructure that had not been built.
- [`dev-nais-comparison-2026-10-30.md`](dev-nais-comparison-2026-10-30.md): the first
  pilot's deployment notes and comparison results, using the old API.
- `nais-api-listimages.patch`: an early patch, superseded by nais/api PR #609.
- `v0s-lanes.js`, `v0s-fix-lanes-1.js`: agent orchestration scripts from the
  implementation sessions; not supported development tools.

Historical references to `docs/background/`, `docs/reviews/`, `docs/adr/` and
`docs/handover.md` point to the material now collected here. Their contents are
retained as snapshots rather than kept in sync with the current documentation.
