// Package databasetest provides throwaway Postgres databases for tests.
//
// Call Main from TestMain, then New in each test that needs a database:
//
//	func TestMain(m *testing.M) { databasetest.Main(m) }
//
// Main uses V0S_TEST_DATABASE_URL if set. Otherwise it starts a temporary
// cluster with initdb and pg_ctl from V0S_PG_BIN, or from PATH. If neither is available, tests
// calling New are skipped. If the binaries exist but the cluster does not start, the run fails.
package databasetest

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
)

var (
	adminURL   string // empty if no Postgres is available
	skipReason string
	counter    atomic.Int64
)

// Main runs the tests in m with a Postgres server available to New.
func Main(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if url := os.Getenv("V0S_TEST_DATABASE_URL"); url != "" {
		adminURL = url
		return m.Run()
	}
	initdb, pgCtl, err := pgBinaries()
	if err != nil {
		skipReason = err.Error()
		return m.Run()
	}
	stop, err := startCluster(initdb, pgCtl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "databasetest: starting postgres: %v\n", err)
		return 1
	}
	defer stop()
	return m.Run()
}

// New returns a migrated, empty database that is dropped when the test ends.
func New(t testing.TB) *database.DB {
	t.Helper()
	db, _ := NewWithURL(t)
	return db
}

// NewWithURL is like New, and also returns the database's connection URL,
// for tests that seed data with plain SQL.
func NewWithURL(t testing.TB) (*database.DB, string) {
	t.Helper()
	if adminURL == "" {
		if skipReason == "" {
			skipReason = "databasetest.Main not called from TestMain"
		}
		t.Skipf("no postgres: %s", skipReason)
	}
	ctx := context.Background()

	name := fmt.Sprintf("v0s_test_%d_%d", os.Getpid(), counter.Add(1))
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connecting to postgres: %v", err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("creating database: %v", err)
	}

	cfg, err := pgx.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=disable", cfg.User, cfg.Host, cfg.Port, name)
	if cfg.Password != "" {
		url = fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", cfg.User, cfg.Password, cfg.Host, cfg.Port, name)
	}

	db, err := database.Open(ctx, url)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		admin, err := pgx.Connect(ctx, adminURL)
		if err != nil {
			t.Errorf("connecting to postgres: %v", err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dropping database: %v", err)
		}
	})
	return db, url
}

// startCluster starts a temporary Postgres cluster and sets adminURL.
func startCluster(initdb, pgCtl string) (stop func(), err error) {
	dir, err := os.MkdirTemp("", "v0s-pg-")
	if err != nil {
		return nil, err
	}
	data := filepath.Join(dir, "data")
	if out, err := exec.Command(initdb, "-D", data, "-U", "postgres", "--auth=trust", "--no-sync").CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("initdb: %v: %s", err, out)
	}
	port, err := freePort()
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	opts := fmt.Sprintf("-p %d -k %s -c listen_addresses=127.0.0.1 -c fsync=off -c synchronous_commit=off -c full_page_writes=off", port, dir)
	if out, err := exec.Command(pgCtl, "-D", data, "-o", opts, "-w", "-l", filepath.Join(dir, "log"), "start").CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("pg_ctl start: %v: %s", err, out)
	}
	adminURL = fmt.Sprintf("postgres://postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	return func() {
		_ = exec.Command(pgCtl, "-D", data, "-m", "immediate", "stop").Run()
		_ = os.RemoveAll(dir)
	}, nil
}

// pgBinaries returns the paths of initdb and pg_ctl, or an error if either is missing.
func pgBinaries() (initdb, pgCtl string, err error) {
	if initdb, err = pgBinary("initdb"); err != nil {
		return "", "", err
	}
	if pgCtl, err = pgBinary("pg_ctl"); err != nil {
		return "", "", err
	}
	return initdb, pgCtl, nil
}

func pgBinary(name string) (string, error) {
	if dir := os.Getenv("V0S_PG_BIN"); dir != "" {
		p, err := exec.LookPath(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("%s not in V0S_PG_BIN: %w", name, err)
		}
		return p, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not on PATH and V0S_PG_BIN not set", name)
	}
	return p, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
