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

By default, `postgresqlEnabled: true` installs `nais-postgresql:0.2.2` as part of
this Helm release. This follows the STS chart pattern; the operator remains a
separate Fasit feature. No extra database assignment or manual Secret is needed.

CNPG creates:

- Cluster `v0s-db`, bootstrapped with database and owner `v0s`.
- Primary Service `v0s-db-rw:5432`.
- Owner Secret `v0s-db-app`, used only by the migration init container.

The shared chart manages a separate `appuser` role with `pg_read_all_data` and
`pg_write_all_data`, without schema ownership. The shared chart provisions a retained
`v0s-db-appuser` basic-auth Secret with `username`, `password` and `uri`; the main
container reads only that Secret's `uri`. The generated URI does not specify
`sslmode`; TLS behavior follows the client's defaults. An upgrade reuses the
existing password. Keep the runtime username stable; do not delete the Secret
to rotate credentials.

v0s has no separate credential-generation template. Set
`postgresql.appUser.existingSecret` only to use a separately managed Secret with
all three keys and credentials for the configured runtime role. In that case
v0s does not create or rotate the Secret. Keep `appUser.enabled=true`.

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
The chart creates no Cluster, runtime Secret or database NetworkPolicies in this
mode. It permits app egress to that cluster and references the existing
`<database.clusterName>-app.uri` owner Secret only for migrations; runtime requires
`<database.clusterName>-appuser.uri`. Override `database.migrationSecretName`
and `database.runtimeSecretName` for independently named Secrets. Provision the
read/write role and its Secret in the external database's owning release before
upgrading v0s; this chart does not create them in external mode.
Existing database ingress policies must allow v0s. Do not turn provisioning on
for an existing cluster without an explicit, backed-up adoption/upgrade plan.

### Upgrading an existing deployment

The Deployment uses `Recreate`: old app replicas stop before the new pod's
`migrate` init container applies forward migrations using the owner Secret.
The main process then opens the database with the runtime role and checks the
schema version without doing DDL. Each pod runs the idempotent migrator;
an advisory lock serializes concurrent migration attempts. This deliberately
introduces app downtime during upgrades rather than running incompatible
binaries against the same schema.

1. Back up the current database and verify the recovery procedure. Keep cluster
   name, database, owner, storage and PostgreSQL image unchanged.
2. Verify whether the database is managed by this release or independently.
   In external mode, prepare the runtime role/Secret first; do not enable
   provisioning to adopt the existing cluster implicitly.
3. Before the first incompatible schema upgrade, establish a safe Helm rollback
   target with the old app's replicas recorded as zero, or arrange a controlled
   upgrade without automatic rollback. Fasit's deployer uses `helm upgrade
   --atomic`: if startup fails, it otherwise restores the old Deployment against
   the already-migrated database. A live `kubectl scale` alone does not update
   the saved Helm revision. Verify this safeguard before assigning the new chart.
4. Publish and assign the new chart in the pilot environment first. Never reset
   the database or delete Cluster/PVC resources to apply this upgrade.
5. Confirm old replicas have stopped, `migrate` completed, the main container uses
   the runtime role, all database instances remain ready and Cluster/PVC UIDs are
   unchanged. Check schema version and preserved/copy counts for assessments.
6. Verify inventory synchronization, scans, gRPC reads and workload-scoped
   assessment writes before updating the next tenant/environment.

A failed migration prevents app startup. Investigate with writes stopped;
do not bypass the init container or supply owner credentials to runtime.
An older application image may be incompatible with the new schema, so an
image rollback is not a database rollback.
See the [Fasit upgrade arguments](https://github.com/nais/fasit/blob/d2938f4011b7b5fc7e087ad9cdb8ba8378dba5ca/internal/naisd/deploy_manager.go#L473-L498)
for the automatic rollback behavior. Once both revisions use the schema-checking
runtime, an incompatible older revision fails startup rather than serving the
wrong schema; schema/data recovery is still a separate operation.

### Retention and backups

`postgresql.keep: true` retains the managed Cluster when Helm uninstalls the
app. Database NetworkPolicies are removed. Retention is not independent release
ownership and does not protect against direct Cluster deletion, namespace
deletion or storage loss. Reinstallation may require adopting the retained
Cluster. Do not copy STS's `keep: false` setting for v0s.

**Backups remain disabled in v0s's defaults.** Replicas are not backups, and
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
