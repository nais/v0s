# v0s Helm chart

One v0s service per tenant in the management cluster, normally in `nais-system`.
The chart deploys the service, dedicated Kubernetes service account,
NetworkPolicies, a PodMonitor and PostgreSQL through the shared
[`nais-postgresql`](https://github.com/nais/helm-charts/tree/main/charts/nais-postgresql)
subchart. It creates no cloud identity, Kubernetes RBAC or public ingress.

## Platform prerequisites

[`Feature.yaml`](Feature.yaml) requires these Fasit features in the same environment:

- **`nais-api`**: the sole workload-inventory source. `nais-api:3001` must expose
  the compatible `Workloads.ListImages` contract. This is a Fasit dependency,
  not a Helm subchart or a minimum API version.
- `nais-netpols-management`: namespace-wide DNS and Kubernetes API egress.
- `cloudnative-pg`: the CNPG operator and CRDs, with PostgreSQL 18 support.
- `fqdn-policy`: HTTPS egress enforcement.
- `monitoring-crds`: PodMonitor support.

Apply the management module's v0s identity resources through Atlantis before
assigning the chart. The module provisions `v0s-sa`, binds Workload Identity to
`nais-system/v0s`, grants Artifact Registry reader in the management project,
and publishes `v0s_serviceaccount_email` to Fasit. `Feature.yaml` computes
`serviceAccountEmail`; no email or key is entered manually. Install as release
`v0s` in `nais-system` to match the binding. Other private registries may need
separate read grants. The runtime identity is not the `gh-v0s` publisher.

## Database provisioning

By default, `postgresqlEnabled: true` installs `nais-postgresql:0.1.0` as part of
this Helm release. This follows the STS chart pattern; the operator remains a
separate Fasit feature. No extra database assignment or manual Secret is needed.

CNPG creates:

- Cluster `v0s-db`, bootstrapped with database and owner `v0s`.
- Primary Service `v0s-db-rw:5432`.
- Secret `v0s-db-app`, whose `uri` key supplies `DATABASE_URL`.

The defaults are three total PostgreSQL instances, each with 10Gi storage and
required node anti-affinity. Three eligible nodes and a suitable StorageClass
are needed. `dynamic-rwo` supports the management cluster's N4 nodes, unlike
its `standard-rwo` default. Fasit exposes instance count and storage size; size
them for the tenant. Storage may grow when the StorageClass supports it, but
must not shrink. The feature allows 15 minutes for bootstrap and cold startup.
The PostgreSQL 18 image is pinned by digest; major upgrades need a separate plan.

`nais-netpols-management` already permits DNS and Kubernetes API egress for all
pods in `nais-system`, including CNPG. NetworkPolicy allows are additive; no
API-server or Service-IP CIDRs need to be configured for v0s. The database
subchart retains its own DNS selectors and database-specific ingress/peer rules.
App pods carry the shared release label required by the database's ingress
policy. Installs outside this platform namespace need equivalent baseline policies.

Keep `postgresql.fullnameOverride` stable. Changing it creates a different
cluster, not a renamed database. Database name and owner apply only at bootstrap.
Changing chart values does not migrate an existing database or its contents.

### Keeping an existing database

To keep an independently managed database, use these Fasit values:

```yaml
postgresqlEnabled: false
database:
  clusterName: v0s-db
```

This keeps the existing database and its suppressions outside the app release.
The chart creates no Cluster or database NetworkPolicies in this mode; it only
references `<database.clusterName>-app.uri` and permits app egress to that cluster.
Existing database ingress policies must allow v0s. Do not turn provisioning on
for an existing cluster without an explicit, backed-up adoption/upgrade plan.

### Resetting the disposable dev-nais pilot

The operator has explicitly approved discarding the pilot data, including
suppressions. Test the managed database path in dev-nais before NAV:

1. Publish and verify the new chart before removing the pilot database.
2. Coordinate the dev-nais Fasit assignment update; leave provisioning enabled.
3. Delete only the old `Cluster/v0s-db` in dev-nais `nais-system` and wait for its
   owned pods, PVC and application Secret to disappear. Do not bulk-delete the
   old manual manifest: its app resources are already managed by Fasit.
4. Install the new chart through Fasit, letting the subchart bootstrap an empty
   database. Expect temporary app downtime while the database is unavailable.
5. Verify the new Cluster/PVC UIDs, Helm ownership and retention annotation,
   three ready instances, application migrations, inventory, scans and API.

This is destructive replacement, not migration or adoption. Do not use this
procedure for NAV or any database whose contents must be retained.

### Retention and backups

`postgresql.keep: true` retains the managed Cluster when Helm uninstalls the
app. Database NetworkPolicies are removed. Retention is not independent release
ownership and does not protect against direct Cluster deletion, namespace
deletion or storage loss. Reinstallation may require adopting the retained
Cluster. Do not copy STS's `keep: false` setting for v0s.

**The subchart does not configure backups.** Replicas are not backups, and
asynchronous failover may lose recent writes. Suppressions are durable human
assessments: configure backups and test restore before production use. An
environment with no backups is not production-ready merely because pods run.

## Application configuration and trust

Use a release chart whose `appVersion` identifies its published image, or set
`image.tag`. Set `github.organizations` to the accepted signer organizations
(e.g. `nais` and `navikt`), and review `networkPolicy.httpsHosts` for registry
redirects and data sources. Adding a Trivy repository does not open egress.

The API trusts same-namespace callers; team filters are not authorization. The
chart restricts gRPC/HTTP ingress to that namespace and allows Nais API, CNPG,
DNS, GKE metadata and allowlisted HTTPS egress. It mounts writable cache/temp
volumes for the read-only scratch container. Platform policies are additive;
verify effective access before adding consumers. Do not install in an untrusted
application namespace.

## Local verification and release

`mise run check` fetches the locked Helm dependency, lints both database modes,
and runs render/package tests. `ci/` values are rendering fixtures, not real
credentials or a published image. `Chart.lock` is committed; downloaded
`charts/*.tgz` dependencies are ignored and bundled into the release archive.

A local render against an existing database:

```sh
mise run charts:dependencies
mise exec -- helm template v0s charts --namespace nais-system --set image.tag="$VERSION" --set serviceAccountEmail="$RUNTIME_SERVICE_ACCOUNT" --set postgresqlEnabled=false
```

For a new database, leave provisioning enabled:

```sh
mise exec -- helm template v0s charts --namespace nais-system --set image.tag="$VERSION" --set serviceAccountEmail="$RUNTIME_SERVICE_ACCOUNT"
```

To package a release for a published image:

```sh
VERSION="$VERSION" mise run build:chart
```

After green checks, pushes to `main` publish the signed image and a self-contained
OCI chart. The chart version and `appVersion` both use the image build version.
The Actions summary supplies the chart reference, version and image digest:

- Chart: `oci://europe-north1-docker.pkg.dev/nais-io/nais/feature/v0s`
- Version: the published build version
- Image: the corresponding container reference with digest

Fasit assignments remain manual. The pipeline does not deploy or change an
assignment. The publisher needs writer access to the `nais` GAR repository;
checks must be able to read the `nais-postgresql` chart dependency.

Rendering does not prove live database bootstrap, NetworkPolicy enforcement,
registry access, recovery or scale. Follow the
[verification checklist](../docs/verification.md) before adding consumers.
