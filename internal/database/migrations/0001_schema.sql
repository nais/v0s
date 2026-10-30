-- Images are identified by repository name and manifest digest. Tags are not facts we keep.
CREATE TABLE images (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text        NOT NULL,
    digest               text        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    -- Bumped every time the image is observed running. Used for garbage collection.
    last_seen_at         timestamptz NOT NULL DEFAULT now(),

    sbom_state           text        NOT NULL DEFAULT 'pending'
        CHECK (sbom_state IN ('pending', 'fetched', 'missing', 'failed')),
    sbom_attempts        integer     NOT NULL DEFAULT 0,
    -- Earliest time the fetch loop may (re)claim this image. Doubles as a lease.
    sbom_next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sbom_error           text        NOT NULL DEFAULT '',
    sbom_fetched_at      timestamptz,

    -- UpdatedAt of the vulnerability DB that produced the image's current findings.
    scanned_db_version   timestamptz,
    scanned_at           timestamptz,
    -- Last failed scan and the DB version it used. Cleared by a successful scan. The image is
    -- not rescanned until a DB newer than scan_failed_db_version is loaded.
    scan_error           text        NOT NULL DEFAULT '',
    scan_failed_db_version timestamptz,
    scan_lease_until     timestamptz,

    UNIQUE (name, digest)
);

CREATE INDEX images_sbom_due ON images (sbom_next_attempt_at) WHERE sbom_state <> 'fetched';

-- Verified CycloneDX JSON, gzip-compressed. Kept so rescans never refetch.
CREATE TABLE sboms (
    image_id bigint PRIMARY KEY REFERENCES images (id) ON DELETE CASCADE,
    document bytea NOT NULL
);

-- What runs where, as observed from pod status. Replaced per cluster on every snapshot.
CREATE TABLE workload_images (
    cluster     text        NOT NULL,
    namespace   text        NOT NULL,
    workload    text        NOT NULL,
    container   text        NOT NULL,
    image_id    bigint      NOT NULL REFERENCES images (id) ON DELETE CASCADE,
    -- Kind of the pod's controlling owner: ReplicaSet, Job, StatefulSet, DaemonSet, or '' if none.
    owner_kind  text        NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster, namespace, workload, container, image_id)
);

CREATE INDEX workload_images_image ON workload_images (image_id);

-- Packages listed in an image's SBOM, with or without findings.
CREATE TABLE components (
    image_id    bigint NOT NULL REFERENCES images (id) ON DELETE CASCADE,
    purl        text   NOT NULL,
    package_key text   NOT NULL,
    name        text   NOT NULL,
    version     text   NOT NULL,
    PRIMARY KEY (image_id, purl)
);

CREATE INDEX components_package_key ON components (package_key);
CREATE INDEX components_name ON components (lower(name) text_pattern_ops);

-- Vulnerability records as published in the Trivy DB, keyed by the ID Trivy reports.
CREATE TABLE vulnerabilities (
    id           text PRIMARY KEY,
    title        text        NOT NULL DEFAULT '',
    description  text        NOT NULL DEFAULT '',
    -- Severity per source, e.g. {"nvd": "HIGH", "ghsa": "MEDIUM"}.
    severities   jsonb       NOT NULL DEFAULT '{}',
    -- CVSS per source, e.g. {"nvd": {"v3_vector": "...", "v3_score": 7.5}}.
    cvss         jsonb       NOT NULL DEFAULT '{}',
    "references" text[]      NOT NULL DEFAULT '{}',
    published_at timestamptz,
    modified_at  timestamptz,
    -- UpdatedAt of the vulnerability DB this row was taken from. Older DBs never overwrite it.
    db_version   timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- Other IDs for the same vulnerability (GHSA, distro advisories). An alias may map to several IDs.
CREATE TABLE vulnerability_aliases (
    alias            text NOT NULL,
    vulnerability_id text NOT NULL REFERENCES vulnerabilities (id) ON DELETE CASCADE,
    PRIMARY KEY (alias, vulnerability_id)
);

CREATE INDEX vulnerability_aliases_vulnerability ON vulnerability_aliases (vulnerability_id);

-- Current findings for each image, according to scanned_db_version.
CREATE TABLE findings (
    image_id          bigint      NOT NULL REFERENCES images (id) ON DELETE CASCADE,
    vulnerability_id  text        NOT NULL REFERENCES vulnerabilities (id),
    purl              text        NOT NULL,
    package_key       text        NOT NULL,
    installed_version text        NOT NULL,
    fixed_version     text        NOT NULL DEFAULT '',
    -- Trivy fix status: affected, fixed, will_not_fix, fix_deferred, end_of_life, under_investigation, unknown.
    status            text        NOT NULL,
    severity          text        NOT NULL
        CHECK (severity IN ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    -- Which source the severity was taken from, e.g. "debian", "ghsa", "nvd".
    severity_source   text        NOT NULL DEFAULT '',
    -- Advisory source that produced the match, e.g. "ghsa", "alpine".
    data_source       text        NOT NULL DEFAULT '',
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (image_id, vulnerability_id, purl)
);

CREATE INDEX findings_vulnerability ON findings (vulnerability_id);
CREATE INDEX findings_suppression_key ON findings (package_key, vulnerability_id);

-- Changes in findings between scans. No foreign keys: history outlives images.
CREATE TABLE finding_events (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    image_name       text        NOT NULL,
    image_digest     text        NOT NULL,
    vulnerability_id text        NOT NULL,
    purl             text        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('appeared', 'resolved')),
    db_version       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX finding_events_created ON finding_events (created_at);
CREATE INDEX finding_events_image ON finding_events (image_name, image_digest);

-- FIRST EPSS, latest published day only.
CREATE TABLE epss (
    cve        text PRIMARY KEY,
    score      double precision NOT NULL,
    percentile double precision NOT NULL,
    date       date             NOT NULL
);

-- CISA Known Exploited Vulnerabilities.
CREATE TABLE kev (
    cve                       text PRIMARY KEY,
    date_added                date    NOT NULL,
    due_date                  date,
    known_ransomware_campaign boolean NOT NULL
);

-- Human assessments. Append-only: rows are only ever updated to revoke them.
CREATE TABLE suppressions (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    image_name       text        NOT NULL,
    package_key      text        NOT NULL,
    vulnerability_id text        NOT NULL,
    state            text        NOT NULL
        CHECK (state IN ('not_affected', 'false_positive', 'accepted_risk')),
    -- CycloneDX/VEX justification. Required for not_affected, forbidden otherwise.
    justification    text        NOT NULL DEFAULT '',
    detail           text        NOT NULL CHECK (detail <> ''),
    created_by       text        NOT NULL CHECK (created_by <> ''),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz,
    revoked_at       timestamptz,
    revoked_by       text        NOT NULL DEFAULT '',
    revoke_reason    text        NOT NULL DEFAULT '',
    CHECK ((state = 'not_affected') = (justification <> '')),
    CHECK (justification IN ('', 'code_not_present', 'code_not_reachable', 'requires_configuration',
                             'requires_dependency', 'requires_environment', 'protected_by_compiler',
                             'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control')),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoked_by = ''))
);

CREATE UNIQUE INDEX suppressions_one_unrevoked
    ON suppressions (image_name, package_key, vulnerability_id) WHERE revoked_at IS NULL;
