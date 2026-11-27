ALTER TABLE images
    ADD COLUMN error_code text NOT NULL DEFAULT ''
    CHECK (error_code IN ('', 'attestation_rejected'));
