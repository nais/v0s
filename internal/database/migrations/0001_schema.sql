-- Initial schema. Subsequent changes are applied through numbered migrations.

-- Images are identified by repository name and manifest digest. Tags are not facts we keep.
CREATE TABLE images (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text        NOT NULL CHECK (name <> ''),
    digest               text        NOT NULL CHECK (digest <> ''),

    sbom_state           text        NOT NULL DEFAULT 'pending'
        CHECK (sbom_state IN ('pending', 'fetched', 'missing', 'failed')),
    -- Earliest time the fetch loop may try this image again.
    sbom_next_attempt_at timestamptz NOT NULL DEFAULT now(),
    -- Verified CycloneDX JSON, gzip-compressed, set once when fetched. Kept so rescans never
    -- refetch; Postgres stores it out of line, so reading other columns does not touch it.
    sbom                 bytea
        CHECK ((sbom IS NOT NULL) = (sbom_state = 'fetched')),
    -- Why the last fetch or, once fetched, the last scan failed. Cleared by a successful one.
    error                text        NOT NULL DEFAULT '',

    -- UpdatedAt of the vulnerability DB that produced the image's current findings.
    scanned_db_version   timestamptz,
    scanned_at           timestamptz,
    -- DB version of the last failed scan. Cleared by a successful scan. The image is not
    -- rescanned until a DB newer than scan_failed_db_version is loaded.
    scan_failed_db_version timestamptz,
    -- Scans started without a recorded result, counted for scan_attempts_db_version only. Reset
    -- by a successful or failed scan. NextScan gives up on an image after maxScanAttempts.
    scan_attempts        integer     NOT NULL DEFAULT 0,
    scan_attempts_db_version timestamptz,

    UNIQUE (name, digest)
);

CREATE INDEX images_sbom_due ON images (sbom_next_attempt_at) WHERE sbom_state <> 'fetched';

-- Which image each team workload is deployed with, as listed by Nais API. An application
-- and a job cannot share a name, so environment, team and name identify a workload.
-- image_reference is the image as deployed; image_id is the image it resolved to, or NULL if it
-- could not be resolved, with resolve_error saying why.
-- Replaced per environment on every sync. Images no workload uses are deleted after each sync.
CREATE TABLE workloads (
    environment     text   NOT NULL CHECK (environment <> ''),
    team            text   NOT NULL CHECK (team <> ''),
    name            text   NOT NULL CHECK (name <> ''),
    image_reference text   NOT NULL,
    image_id        bigint REFERENCES images (id) ON DELETE CASCADE,
    resolve_error   text   NOT NULL DEFAULT '',
    CHECK ((image_id IS NULL) = (resolve_error <> '')),
    PRIMARY KEY (environment, team, name)
);

CREATE INDEX workloads_image ON workloads (image_id);

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
    db_version   timestamptz NOT NULL
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
    PRIMARY KEY (image_id, vulnerability_id, purl)
);

CREATE INDEX findings_vulnerability ON findings (vulnerability_id);
CREATE INDEX findings_suppression_key ON findings (package_key, vulnerability_id);

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

-- Each team's current assessments of findings in its own workloads: another team using the
-- same image is not affected. Only the current state is kept; Nais API logs the changes.
CREATE TABLE suppressions (
    team             text        NOT NULL CHECK (team <> ''),
    image_name       text        NOT NULL CHECK (image_name <> ''),
    package_key      text        NOT NULL CHECK (package_key <> ''),
    vulnerability_id text        NOT NULL CHECK (vulnerability_id <> ''),
    state            text        NOT NULL
        CHECK (state IN ('not_affected', 'false_positive', 'accepted_risk')),
    detail           text        NOT NULL CHECK (detail <> ''),
    updated_by       text        NOT NULL CHECK (updated_by <> ''),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team, image_name, package_key, vulnerability_id)
);
