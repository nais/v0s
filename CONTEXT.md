# Domain language

**Tenant**
: One Nais installation, for example `nav`. Each tenant runs one v0s. No data
crosses tenants. Within a tenant, everyone may see every team's findings.

**Workload**
: A team's Nais application or job, identified by `(environment, team, name)`,
as Nais API reports it. An application and a job cannot share a name, so the
kind is not part of the identity. The platform's own workloads in `nais-system`
are out of scope: Nais API leaves them out, and the platform has its own tools
for them.

**Image**
: A container image identified by repository name plus manifest digest, for
example `europe-north1-docker.pkg.dev/nais-io/nais/images/foo@sha256:…`. The tag
is not part of the identity.

**Workload image**
: The one image a workload is deployed with, whether or not it runs
right now: apps scaled to zero and jobs between runs keep their image. Taken
from the workload's effective image in Nais API; a tag is resolved to its digest
in the registry once. A tag moved in the registry afterwards is not noticed.
A workload whose image cannot be resolved is kept without an image, with the
reason, so that it shows as a coverage gap instead of disappearing.
Platform sidecars (texas, wonderwall, Cloud SQL proxy) are not part of it.

**SBOM**
: The CycloneDX document attested to an image with cosign, signed by a
trusted GitHub Actions workflow or an explicitly configured identity within
its allowed image-repository scope. Identity rules grant signing trust, not
team membership or build provenance. v0s stores the verified SBOM so that it can
rescan without fetching it again, until no workload uses the image.

**Component**
: A package listed in an SBOM, identified by its purl. Components are stored
whether or not they have findings. This makes inventory search possible ("where
does log4j-core 2.14 run?").

**Vulnerability DB**
: The Trivy DB (`trivy-db:2`) that v0s downloads from an OCI registry. Its
version is the `UpdatedAt` from the DB metadata.

**Scan**
: Matching one image's SBOM against one vulnerability DB version. For a given
scanner implementation, the same SBOM and DB version give the same findings.

**Image status**
: How far an image has got towards findings: `pending` (SBOM not fetched or
image not scanned yet), `scanned`, `no_sbom` (no attestation found) or `failed`
(fetching, verifying or scanning failed). `scanned` means a scan completed, not
that the image is free of vulnerabilities or its SBOM is complete. A failed
rescan preserves the previous findings and `scanned` status, with an error.

**Finding**
: The fact that a vulnerability affects one component of a workload's image
according to one DB version. A finding has a severity, a severity source, a fix
status, and a fixed version if one is known. An image used by several workloads
has its findings once per workload: that is what is listed and counted.

**Vulnerability ID**
: The ID Trivy reports for a finding, usually a CVE. Alias IDs (GHSA, distro
advisory IDs) resolve to this ID.

**Package key**
: A purl with version, qualifiers and subpath removed, for example
`pkg:npm/%40scope/name`. Suppressions match on the package key, so they survive
version bumps.

**Package type**
: The purl type of a package key, for example `npm`, `maven` or `golang`.
Findings can be filtered and counted by it.

**Suppression**
: A team's current assessment that a vulnerability does not matter for a package
in one workload, keyed by `(team, environment, workload name, image name,
package key, vulnerability ID)`. Other workloads and environments never inherit
it, even within the same team or image. Image and package versions are not part
of the key, but changing the image repository stops the assessment applying.
It has a state (not affected, false positive or accepted risk),
a reason in the team's words, and who last set it. Setting it again replaces
it; deleting it removes it. There is no expiry or history of changes in v0s;
callers keep any activity log they need. These assessments are durable data
owned here; unlike inventory and scan results, they cannot be rebuilt from
external sources.

**Suppressed**
: A finding is suppressed when its workload has a matching suppression.
Clients can list findings by vulnerability (including suppressed ones), select
other workloads and set separate assessments for them in an atomic batch.

**EPSS and KEV**
: Source data from FIRST and CISA, supplied alongside findings. v0s does not
turn them into priority tiers, thresholds or a risk score.
