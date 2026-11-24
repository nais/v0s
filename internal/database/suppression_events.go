package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type SuppressionEvent struct {
	ID         string
	Operation  string
	Actor      *string
	OccurredAt time.Time
	Before     *Suppression
	After      *Suppression
}

func enableSuppressionEvents(ctx context.Context, tx pgx.Tx, actor string) error {
	_, err := tx.Exec(ctx, `
		SELECT set_config('v0s.emit_suppression_events', 'on', true),
			set_config('v0s.suppression_event_actor', $1, true)`, actor)
	if err != nil {
		return fmt.Errorf("enabling suppression events: %w", err)
	}
	return nil
}

func (db *DB) ListSuppressionEvents(ctx context.Context, batchSize int) ([]SuppressionEvent, error) {
	if batchSize == 0 {
		batchSize = 100
	}
	if batchSize < 1 || batchSize > 1000 {
		return nil, fmt.Errorf("batch_size must be between 1 and 1000: %w", ErrInvalid)
	}
	rows, err := db.pool.Query(ctx, `
		SELECT event_id::text, operation, actor, occurred_at, before_value, after_value
		FROM suppression_events
		ORDER BY occurred_at, event_id
		LIMIT $1`, batchSize)
	if err != nil {
		return nil, fmt.Errorf("listing suppression events: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SuppressionEvent, error) {
		var e SuppressionEvent
		err := row.Scan(&e.ID, &e.Operation, &e.Actor, &e.OccurredAt, &e.Before, &e.After)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("reading suppression events: %w", err)
	}
	return events, nil
}

func (db *DB) AcknowledgeSuppressionEvents(ctx context.Context, ids []string) error {
	if len(ids) == 0 || len(ids) > 1000 {
		return fmt.Errorf("event_ids must contain between 1 and 1000 IDs: %w", ErrInvalid)
	}
	for i, id := range ids {
		var uuid pgtype.UUID
		if err := uuid.Scan(id); err != nil || !uuid.Valid {
			return fmt.Errorf("event_ids[%d] must be a UUID: %w", i, ErrInvalid)
		}
	}
	_, err := db.pool.Exec(ctx, `DELETE FROM suppression_events WHERE event_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return fmt.Errorf("acknowledging suppression events: %w", err)
	}
	return nil
}
