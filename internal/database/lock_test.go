package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestWithLock(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	ran := func(name string) bool {
		t.Helper()
		var ran bool
		if err := db.WithLock(ctx, name, func(context.Context) error { ran = true; return nil }); err != nil {
			t.Fatal(err)
		}
		return ran
	}

	err := db.WithLock(ctx, "sync", func(context.Context) error {
		if ran("sync") {
			t.Error("ran while the same lock was held")
		}
		if !ran("scan") {
			t.Error("did not run while another lock was held")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ran("sync") {
		t.Error("did not run after the lock was released")
	}
}

func TestWithLockSinglePoolConnection(t *testing.T) {
	ctx := context.Background()
	_, url := databasetest.NewWithURL(t)
	db, err := database.Open(ctx, url+"&pool_max_conns=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.WithLock(ctx, "sync", db.Ping); err != nil {
		t.Errorf("WithLock using the pool: %v", err)
	}
}
