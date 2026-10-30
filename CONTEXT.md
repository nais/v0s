# Domain language

**Tenant**
: One Nais installation, for example `nav`. Each tenant runs one v0s. No data
crosses tenants.

**Workload**
: A Nais application or job. A workload is identified by
`(environment, namespace, name)`, as Nais API reports it. The namespace is the
team. The `cluster` column holds the environment name.

**Image**
: A container image identified by repository name plus manifest digest, for
example `europe-north1-docker.pkg.dev/nais-io/nais/images/foo@sha256:…`. The tag
is not part of the identity.

**Workload image**
: The fact that a workload is deployed with a given image, whether or not it runs
right now: apps scaled to zero and jobs between runs keep their image. Taken
from the workload's effective image in Nais API; a tag is resolved to its digest
in the registry, and re-resolved hourly so that a moved tag is noticed.
Platform sidecars (texas, wonderwall, Cloud SQL proxy) are not part of it.

**SBOM**
: The CycloneDX document attested to an image with cosign, signed by the
team's GitHub Actions workflow. v0s stores the verified SBOM so that it can
rescan without fetching it again.

**Component**
: A package listed in an SBOM, identified by its purl. Components are stored
whether or not they have findings. This makes inventory search possible ("where
does log4j-core 2.14 run?").

**Vulnerability DB**
: The Trivy DB (`trivy-db:2`) that v0s downloads from an OCI registry. Its
version is the `UpdatedAt` from the DB metadata.

**Scan**
: Matching one image's SBOM against one vulnerability DB version. A scan is
pure: the same SBOM and DB version give the same findings.

**Finding**
: The fact that a vulnerability affects one component of one image according to
one DB version. A finding has a severity, a severity source, a fix status, and a
fixed version if one is known.

**Vulnerability ID**
: The ID Trivy reports for a finding, usually a CVE. Alias IDs (GHSA, distro
advisory IDs) resolve to this ID.

**Package key**
: A purl with version, qualifiers and subpath removed, for example
`pkg:npm/%40scope/name`. Suppressions match on the package key, so they survive
version bumps.

**Suppression**
: A human assessment that a vulnerability does not apply to a package in an
image name, keyed by `(image name, package key, vulnerability ID)`. It has a VEX
state, an optional justification, an author, an optional expiry, and can be
revoked. Rows are never updated except to revoke them. A suppression is active
when it is not revoked and has not expired.

**Finding event**
: A recorded change in the findings for an image: `appeared` or `resolved`.
History of human assessments lives in the suppression rows themselves.
