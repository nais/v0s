CREATE TABLE suppression_events (
    event_id    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    operation   text        NOT NULL CHECK (operation IN ('set', 'delete')),
    actor       text        CHECK (actor <> ''),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    before_value jsonb,
    after_value  jsonb,
    CHECK (operation <> 'set' OR actor IS NOT NULL),
    CHECK (
        (operation = 'set' AND after_value IS NOT NULL)
        OR (operation = 'delete' AND before_value IS NOT NULL AND after_value IS NULL)
    )
);

CREATE INDEX suppression_events_delivery ON suppression_events (occurred_at, event_id);

CREATE FUNCTION enqueue_suppression_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('v0s.emit_suppression_events', true) IS DISTINCT FROM 'on' THEN
        RETURN NULL;
    END IF;
    INSERT INTO suppression_events (operation, actor, before_value, after_value)
    VALUES (
        CASE WHEN TG_OP = 'DELETE' THEN 'delete' ELSE 'set' END,
        nullif(current_setting('v0s.suppression_event_actor', true), ''),
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END
    );
    RETURN NULL;
END;
$$;

CREATE TRIGGER suppression_change_event
AFTER INSERT OR UPDATE OR DELETE ON suppressions
FOR EACH ROW EXECUTE FUNCTION enqueue_suppression_event();
