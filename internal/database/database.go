// Package database owns the Postgres schema and every SQL statement v0s runs.
package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// migrationLock is the advisory lock key held while migrating.
const migrationLock = 0x7630_7330 // "v0s0"

// DB is the v0s store.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and checks that Migrate has prepared the expected schema.
// The runtime user needs read/write access, not schema ownership.
func Open(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	files, err := migrationFiles()
	if err != nil {
		pool.Close()
		return nil, err
	}
	expected, err := migrationVersion(files[len(files)-1])
	if err != nil {
		pool.Close()
		return nil, err
	}
	var current int
	if err := pool.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		pool.Close()
		return nil, fmt.Errorf("checking schema; run v0s migrate first: %w", err)
	}
	if current != expected {
		pool.Close()
		return nil, fmt.Errorf("database schema version %d, want %d; run v0s migrate before starting", current, expected)
	}
	return &DB{pool: pool}, nil
}

// Migrate applies pending migrations using the database owner's credentials.
func Migrate(ctx context.Context, url string) error {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return fmt.Errorf("connecting for migration: %w", err)
	}
	defer pool.Close()
	if err := migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	return nil
}

// Close closes the connection pool.
func (db *DB) Close() { db.pool.Close() }

// Ping checks that the database is reachable.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

func migrationFiles() ([]string, error) {
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no embedded database migrations")
	}
	sort.Strings(files)
	return files, nil
}

func migrationVersion(file string) (int, error) {
	base := strings.TrimPrefix(file, "migrations/")
	version, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
	if err != nil {
		return 0, fmt.Errorf("migration %s: invalid version prefix", base)
	}
	return version, nil
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	files, err := migrationFiles()
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return fmt.Errorf("locking: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrationLock) }()

	if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)"); err != nil {
		return err
	}
	var current int
	if err := conn.QueryRow(ctx, "SELECT coalesce(max(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return err
	}
	latest, err := migrationVersion(files[len(files)-1])
	if err != nil {
		return err
	}
	if current > latest {
		return fmt.Errorf("database schema version %d is newer than this binary's version %d; refusing to migrate backwards", current, latest)
	}

	for _, f := range files {
		base := strings.TrimPrefix(f, "migrations/")
		version, err := migrationVersion(f)
		if err != nil {
			return err
		}
		if version <= current {
			continue
		}
		sql, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", base, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
