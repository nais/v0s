package database_test

import (
	"context"
	"testing"

	"github.com/nais/v0s/internal/database/databasetest"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

func TestOpenMigrates(t *testing.T) {
	db := databasetest.New(t)
	if err := db.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}
