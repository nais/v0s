package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// jobLockSpace is the first key of the two-key advisory locks taken by WithLock. Two-key locks
// do not overlap with the single-key migration lock.
const jobLockSpace = 0x7630_734a // "v0sJ"

// closeTimeout bounds closing the lock connection, which releases the lock.
const closeTimeout = 5 * time.Second

// WithLock runs fn if it can take the named cluster-wide advisory lock, and does nothing if
// another session holds it. The lock is held on a dedicated connection outside the pool, so fn
// can use the whole pool.
func (db *DB) WithLock(ctx context.Context, name string, fn func(ctx context.Context) error) error {
	conn, err := pgx.ConnectConfig(ctx, db.pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("connecting for lock %q: %w", name, err)
	}
	// Closing the session releases the lock.
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
		defer cancel()
		_ = conn.Close(ctx)
	}()

	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, jobLockSpace, name).Scan(&locked); err != nil {
		return fmt.Errorf("taking lock %q: %w", name, err)
	}
	if !locked {
		return nil
	}
	return fn(ctx)
}
