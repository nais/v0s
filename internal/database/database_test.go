package database_test

import (
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

func TestRuntimeRoleReadsAndWritesWithoutOwningSchema(t *testing.T) {
	_, databaseURL := databasetest.NewWithURL(t)
	ctx := t.Context()
	owner, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	role := "runtime_" + strings.ToLower(rand.Text())
	password := rand.Text()
	if _, err := owner.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+
		" LOGIN PASSWORD '"+password+"' IN ROLE pg_read_all_data, pg_write_all_data"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := owner.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Errorf("dropping test role: %v", err)
		}
	}()
	cfg, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.User = url.UserPassword(role, password)
	runtimeURL := cfg.String()
	db, err := database.Open(ctx, runtimeURL)
	if err != nil {
		t.Fatalf("opening with runtime credentials: %v", err)
	}
	defer db.Close()
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{{
		Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a",
	}}); err != nil {
		t.Fatalf("runtime inventory writes: %v", err)
	}
	workloads, _, err := db.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
	if err != nil || len(workloads) != 1 || workloads[0].Name != "app" {
		t.Fatalf("runtime inventory read: %v, %v", workloads, err)
	}
	if err := db.SyncWorkloadImages(ctx, "dev", nil); err != nil {
		t.Fatalf("runtime inventory delete: %v", err)
	}
	runtime, err := pgx.Connect(ctx, runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(ctx)
	for _, statement := range []string{
		"ALTER TABLE images ADD COLUMN forbidden integer",
		"CREATE TABLE forbidden (id integer)",
	} {
		_, err := runtime.Exec(ctx, statement)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("runtime DDL: %v, want insufficient_privilege", err)
		}
	}
}

func TestOpenDoesNotCreateMigrationTable(t *testing.T) {
	db, url := databasetest.NewWithURL(t)
	db.Close()
	conn, err := pgx.Connect(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}

	defer conn.Close(t.Context())
	if _, err := conn.Exec(t.Context(), "DROP TABLE schema_migrations"); err != nil {
		t.Fatal(err)
	}
	opened, err := database.Open(t.Context(), url)
	if err == nil {
		opened.Close()
		t.Fatal("runtime must reject an unprepared schema")
	}
	if !strings.Contains(err.Error(), "run v0s migrate") {
		t.Fatalf("missing migration instructions: %v", err)
	}
	var missing bool
	if err := conn.QueryRow(t.Context(), "SELECT to_regclass('schema_migrations') IS NULL").Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if !missing {
		t.Fatal("runtime startup created schema objects")
	}
}

func TestNewerSchemaRejectsOlderBinary(t *testing.T) {
	db, url := databasetest.NewWithURL(t)
	db.Close()
	conn, err := pgx.Connect(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(t.Context())
	if _, err := conn.Exec(t.Context(), "INSERT INTO schema_migrations SELECT max(version) + 1 FROM schema_migrations"); err != nil {
		t.Fatal(err)
	}
	opened, err := database.Open(t.Context(), url)
	if err == nil {
		opened.Close()
		t.Fatal("older runtime must not serve a newer schema")
	}
	if err := database.Migrate(t.Context(), url); err == nil {
		t.Fatal("older migrator must not accept a newer schema")
	}
}
