package database

import "github.com/jackc/pgx/v5/pgxpool"

// Pool exposes the connection pool so that black-box tests can inspect rows directly.
func (db *DB) Pool() *pgxpool.Pool { return db.pool }
