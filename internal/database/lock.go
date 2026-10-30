package database

import (
	"context"
	"fmt"
)

// jobLockSpace is the first key of the two-key advisory locks taken by WithLock. Two-key locks
// do not overlap with the single-key migration lock.
const jobLockSpace = 0x7630_734a // "v0sJ"

// WithLock runs fn if it can take the named cluster-wide advisory lock, and reports whether fn
// ran. The lock is held on a dedicated connection until fn returns. Used for singleton jobs.
func (db *DB) WithLock(ctx context.Context, name string, fn func(ctx context.Context) error) (bool, error) {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("acquiring connection for lock %q: %w", name, err)
	}
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, jobLockSpace, name).Scan(&locked); err != nil {
		return false, fmt.Errorf("taking lock %q: %w", name, err)
	}
	if !locked {
		return false, nil
	}
	defer func() {
		ctx := context.WithoutCancel(ctx)
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, jobLockSpace, name); err != nil {
			// Closing the session releases the lock, and Release discards the closed connection.
			_ = conn.Conn().Close(ctx)
		}
	}()

	return true, fn(ctx)
}
