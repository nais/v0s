# v0s Helm chart

One v0s instance in the tenant's management cluster, normally in `nais-system`.
This chart deploys the service, its dedicated Kubernetes service account,
NetworkPolicies and a PodMonitor. It creates no database, cloud identity or
Kubernetes RBAC, and has no public ingress.

## Prerequisites

[`Feature.yaml`](Feature.yaml) requires these Fasit features in the same environment:

- **`nais-api`**: the sole workload-inventory source. Its internal gRPC endpoint
  at `nais-api:3001` must expose the compatible `Workloads.ListImages` contract.
  The dependency names the feature, not a minimum API version or a Helm subchart.
- `cloudnative-pg`: manages the separately provisioned database.
- `fqdn-policy`: HTTPS egress enforcement.
- `monitoring-crds`: PodMonitor support.

Before installing:

1. Provision a CNPG cluster in the release namespace, default name `v0s-db`,
   with an application database and CNPG's `<clusterName>-app` Secret (`uri` key).
   Allow v0s pods to connect if the database has restrictive ingress policies.
   Configure backups and test restore of suppressions. The app chart neither
   creates nor deletes the cluster, including during uninstall.
2. Apply the management module's v0s identity resources through Atlantis before
   assigning this chart. The module provisions `v0s-sa`, binds Workload Identity
   to `nais-system/v0s`, grants Artifact Registry reader in the management project,
   and publishes `v0s_serviceaccount_email` to Fasit. `Feature.yaml` computes
   `serviceAccountEmail` from that value; no email or key is entered manually.
   Install as release `v0s` in `nais-system` to match the binding. Additional
   private registries may need separate read grants. This is not the `gh-v0s`
   image-publishing account, nor the pilot's `v13s-sa`.
3. Set `image.tag` to a published image tag, or use a release chart whose
   `appVersion` identifies that image. Set `github.organizations` to the
   organizations whose workflow signatures may supply SBOMs.
4. Review `networkPolicy.httpsHosts` for registry redirects and data-source
   hosts used by the tenant. Adding a repository to `trivyDBRepositories` does
   not automatically open egress to it.

The API trusts same-namespace callers; team filters are not authorization.
The chart restricts gRPC and HTTP ingress to that namespace, permits Nais API,
CNPG, DNS, GKE metadata and allowlisted HTTPS egress, and supplies writable cache
and temporary volumes for the read-only scratch container. Platform-wide additive
NetworkPolicies may grant more access; verify the effective policies before
adding consumers. Do not install in an untrusted application namespace.

## Local verification and release

`mise run check` includes chart lint and render tests. Rendering fixtures in
`ci/test-values.yaml` are not deployable credentials or a published image.

Outside Fasit, supply the provisioned runtime email explicitly. A local render:

```sh
mise exec -- helm template v0s charts --namespace nais-system --set image.tag="$VERSION" --set serviceAccountEmail="$RUNTIME_SERVICE_ACCOUNT"
```

To package a release locally corresponding to a published image:

```sh
VERSION="$VERSION" mise run build:chart
```

Release versions emitted by the image workflow can be used as Helm versions.
Keep the packaged chart's `appVersion` equal to the published image tag; an
explicit `image.tag` overrides it. Image updates do not update a running release.
After green checks, pushes to `main` publish the signed image and then this OCI
chart to GAR. The chart version and `appVersion` both use the image build version.
The Actions summary provides:

- Chart: `oci://europe-north1-docker.pkg.dev/nais-io/nais/feature/v0s`
- Version: the published build version
- Image: the corresponding container reference with digest

Use the **chart reference and version** for a manual Fasit assignment. An image
reference alone is not a Fasit feature. The pipeline does not create assignments,
call `fasit-deploy` or update running releases. The `gh-v0s` publisher needs writer
access to the `nais` GAR repository for both image and chart paths.

Rendering and lint do not prove live NetworkPolicy enforcement, registry access,
API compatibility, backup recovery or scale. See the
[verification checklist](../docs/verification.md) before adding consumers.
