-- Preserve the original assessments, including those without a current workload match.
ALTER TABLE suppressions RENAME TO legacy_suppressions;
ALTER INDEX suppressions_pkey RENAME TO legacy_suppressions_pkey;

CREATE TABLE suppressions (
    team             text        NOT NULL CHECK (team <> ''),
    environment      text        NOT NULL CHECK (environment <> ''),
    workload         text        NOT NULL CHECK (workload <> ''),
    image_name       text        NOT NULL CHECK (image_name <> ''),
    package_key      text        NOT NULL CHECK (package_key <> ''),
    vulnerability_id text        NOT NULL CHECK (vulnerability_id <> ''),
    state            text        NOT NULL
        CHECK (state IN ('not_affected', 'false_positive', 'accepted_risk')),
    detail           text        NOT NULL CHECK (detail <> ''),
    updated_by       text        NOT NULL CHECK (updated_by <> ''),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team, environment, workload, image_name, package_key, vulnerability_id)
);

-- Best effort: preserve the old effective scope for currently resolved workloads only.
INSERT INTO suppressions (
    team, environment, workload, image_name, package_key, vulnerability_id,
    state, detail, updated_by, updated_at
)
SELECT s.team, w.environment, w.name, s.image_name, s.package_key, s.vulnerability_id,
    s.state, s.detail, s.updated_by, s.updated_at
FROM legacy_suppressions s
JOIN workloads w ON w.team = s.team
JOIN images i ON i.id = w.image_id AND i.name = s.image_name;
