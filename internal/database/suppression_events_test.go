package database_test

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func eventFixture(t *testing.T) (*database.DB, string, *pgx.Conn) {
	t.Helper()
	db, url := databasetest.NewWithURL(t)
	conn, err := pgx.Connect(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(t.Context()) })
	if _, err := conn.Exec(t.Context(), `
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-1', now());
		INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES ('GHSA-1', 'CVE-1');`); err != nil {
		t.Fatal(err)
	}
	return db, url, conn
}

func pendingEvents(t *testing.T, db *database.DB) []database.SuppressionEvent {
	t.Helper()
	events, err := db.ListSuppressionEvents(t.Context(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func acknowledgeEvents(t *testing.T, db *database.DB, events []database.SuppressionEvent) {
	t.Helper()
	var ids []string
	for _, e := range events {
		ids = append(ids, e.ID)
	}
	if err := db.AcknowledgeSuppressionEvents(t.Context(), ids); err != nil {
		t.Fatal(err)
	}
}

func sameSuppression(got *database.Suppression, want database.Suppression) bool {
	if got == nil || !got.UpdatedAt.Equal(want.UpdatedAt) {
		return false
	}
	want.UpdatedAt = got.UpdatedAt
	return *got == want
}

func TestSuppressionEventSnapshots(t *testing.T) {
	db, _, _ := eventFixture(t)
	item := lodashSuppression("accepted_risk")
	item.Package, item.VulnerabilityID = "pkg:npm/lodash@1?arch=x", "GHSA-1"
	first := set(t, db, item)[0]
	created := pendingEvents(t, db)
	if len(created) != 1 {
		t.Fatalf("created events = %+v", created)
	}
	e := created[0]
	if e.ID == "" || e.Operation != "set" || e.Actor == nil || *e.Actor != "me" || e.OccurredAt.IsZero() ||
		e.Before != nil || !sameSuppression(e.After, first) || e.After.SuppressionKey != lodashKey {
		t.Fatalf("created event = %+v, after = %+v", e, e.After)
	}
	acknowledgeEvents(t, db, created)

	second, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{item}, "another")
	if err != nil {
		t.Fatal(err)
	}
	updated := pendingEvents(t, db)
	if len(updated) != 1 || updated[0].ID == e.ID || updated[0].Actor == nil || *updated[0].Actor != "another" ||
		!sameSuppression(updated[0].Before, first) || !sameSuppression(updated[0].After, second[0]) {
		t.Fatalf("unchanged-value set must still have new ID and before/after: %+v", updated)
	}
	acknowledgeEvents(t, db, updated)
	retry, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{item}, "another")
	if err != nil {
		t.Fatal(err)
	}
	retried := retry[0]
	retryEvents := pendingEvents(t, db)
	if len(retryEvents) != 1 || retryEvents[0].ID == updated[0].ID || retryEvents[0].Before == nil ||
		!sameSuppression(retryEvents[0].Before, second[0]) || !sameSuppression(retryEvents[0].After, retried) {
		t.Fatalf("write retry = %+v", retryEvents)
	}
	acknowledgeEvents(t, db, retryEvents)

	deleted, err := db.DeleteSuppressionsAs(t.Context(), "team-a", []database.SuppressionKey{item.SuppressionKey, item.SuppressionKey}, "deleter")
	if err != nil || len(deleted) != 1 {
		t.Fatalf("delete: %v, %v", deleted, err)
	}
	removed := pendingEvents(t, db)
	if len(removed) != 1 || removed[0].Operation != "delete" || removed[0].Actor == nil || *removed[0].Actor != "deleter" ||
		!sameSuppression(removed[0].Before, retried) || removed[0].After != nil {
		t.Fatalf("delete event = %+v", removed)
	}
	acknowledgeEvents(t, db, removed)
	if _, err := db.DeleteSuppressionsAs(t.Context(), "team-a", []database.SuppressionKey{lodashKey, lodashKey}, "deleter"); err != nil {
		t.Fatal(err)
	}
	if events := pendingEvents(t, db); len(events) != 0 {
		t.Fatalf("missing delete targets emitted events: %+v", events)
	}
	set(t, db, item)
	acknowledgeEvents(t, db, pendingEvents(t, db))
	if _, err := db.DeleteSuppressions(t.Context(), "team-a", []database.SuppressionKey{lodashKey}); err != nil {
		t.Fatal(err)
	}
	legacy := pendingEvents(t, db)
	if len(legacy) != 1 || legacy[0].Actor != nil || legacy[0].Before.UpdatedBy != "me" {
		t.Fatalf("legacy actor must be unknown, not previous updated_by: %+v", legacy)
	}
}

func TestSuppressionEventBatchAtomicity(t *testing.T) {
	db, _, conn := eventFixture(t)
	first, second := lodashSuppression("accepted_risk"), lodashSuppression("false_positive")
	second.Workload = "reject"
	bad := second
	bad.VulnerabilityID = "CVE-unknown"
	if _, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{first, bad}, "me"); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("invalid batch: %v", err)
	}
	if len(listSuppressions(t, db)) != 0 || len(pendingEvents(t, db)) != 0 {
		t.Fatal("invalid batch left a suppression or event")
	}
	alias := first
	alias.VulnerabilityID = "GHSA-1"
	if _, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{first, alias}, "me"); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("duplicate canonical key: %v", err)
	}
	if len(listSuppressions(t, db)) != 0 || len(pendingEvents(t, db)) != 0 {
		t.Fatal("duplicate batch left a suppression or event")
	}
	if _, err := conn.Exec(t.Context(), `ALTER TABLE suppression_events ADD CONSTRAINT reject_event
		CHECK (coalesce(after_value->>'workload', before_value->>'workload') <> 'reject')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{first, second}, "me"); err == nil {
		t.Fatal("outbox failure must fail the write")
	}
	if len(listSuppressions(t, db)) != 0 || len(pendingEvents(t, db)) != 0 {
		t.Fatal("outbox failure did not roll back entire set batch")
	}
	if _, err := conn.Exec(t.Context(), `ALTER TABLE suppression_events DROP CONSTRAINT reject_event`); err != nil {
		t.Fatal(err)
	}
	set(t, db, first, second)
	acknowledgeEvents(t, db, pendingEvents(t, db))
	if _, err := conn.Exec(t.Context(), `ALTER TABLE suppression_events ADD CONSTRAINT reject_event
		CHECK (coalesce(after_value->>'workload', before_value->>'workload') <> 'reject')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteSuppressionsAs(t.Context(), "team-a", []database.SuppressionKey{first.SuppressionKey, second.SuppressionKey}, "deleter"); err == nil {
		t.Fatal("outbox failure must fail delete batch")
	}
	if len(listSuppressions(t, db)) != 2 || len(pendingEvents(t, db)) != 0 {
		t.Fatal("outbox failure did not roll back entire delete batch")
	}
	if _, err := db.DeleteSuppressionsAs(t.Context(), "team-a", []database.SuppressionKey{first.SuppressionKey, bad.SuppressionKey}, "deleter"); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("invalid delete batch: %v", err)
	}
	if len(listSuppressions(t, db)) != 2 || len(pendingEvents(t, db)) != 0 {
		t.Fatal("invalid delete batch left partial state")
	}
}

func TestSuppressionEventsRestartAndAcknowledgement(t *testing.T) {
	db, url, _ := eventFixture(t)
	set(t, db, lodashSuppression("accepted_risk"))
	first := pendingEvents(t, db)
	db.Close()
	restarted, err := database.Open(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if got := pendingEvents(t, restarted); !reflect.DeepEqual(got, first) {
		t.Fatalf("restart/redelivery changed events: %+v != %+v", got, first)
	}
	if err := restarted.AcknowledgeSuppressionEvents(t.Context(), []string{first[0].ID, "invalid"}); !errors.Is(err, database.ErrInvalid) {
		t.Fatalf("invalid acknowledgement: %v", err)
	}
	if len(pendingEvents(t, restarted)) != 1 {
		t.Fatal("partially acknowledged an invalid request")
	}
	acknowledgeEvents(t, restarted, first)
	acknowledgeEvents(t, restarted, first)
	if err := restarted.AcknowledgeSuppressionEvents(t.Context(), []string{"00000000-0000-0000-0000-000000000001"}); err != nil {
		t.Fatal(err)
	}
	if len(pendingEvents(t, restarted)) != 0 {
		t.Fatal("acknowledged event was redelivered")
	}
	for _, n := range []int{-1, 1001} {
		if _, err := restarted.ListSuppressionEvents(t.Context(), n); !errors.Is(err, database.ErrInvalid) {
			t.Fatalf("invalid batch size %d: %v", n, err)
		}
	}
	for _, ids := range [][]string{nil, make([]string, 1001)} {
		if err := restarted.AcknowledgeSuppressionEvents(t.Context(), ids); !errors.Is(err, database.ErrInvalid) {
			t.Fatalf("invalid acknowledgement size: %v", err)
		}
	}
}

func TestSuppressionEventsCommitOrder(t *testing.T) {
	db, _, conn := eventFixture(t)
	tx, err := conn.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `
		SELECT set_config('v0s.emit_suppression_events', 'on', true),
			set_config('v0s.suppression_event_actor', 'slow', true);
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team-a', 'c1', 'slow', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'slow', 'slow')`); err != nil {
		t.Fatal(err)
	}
	if len(pendingEvents(t, db)) != 0 {
		t.Fatal("uncommitted event became visible")
	}
	set(t, db, lodashSuppression("accepted_risk"))
	fast := pendingEvents(t, db)
	if len(fast) != 1 || fast[0].After.Workload != "app" {
		t.Fatalf("only later transaction should be visible: %+v", fast)
	}
	acknowledgeEvents(t, db, fast)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	slow := pendingEvents(t, db)
	if len(slow) != 1 || slow[0].After.Workload != "slow" || slow[0].ID == fast[0].ID {
		t.Fatalf("late commit was skipped: %+v", slow)
	}
	if slow[0].OccurredAt.After(fast[0].OccurredAt) {
		t.Fatal("test did not exercise out-of-order commit")
	}
}

func TestSuppressionEventsConcurrentWritesAndConsumers(t *testing.T) {
	db, url, _ := eventFixture(t)
	replica, err := database.Open(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	const writes = 16
	var wg sync.WaitGroup
	for i := range writes {
		wg.Go(func() {
			item := lodashSuppression("accepted_risk")
			item.Detail = fmt.Sprintf("write-%d", i)
			if _, err := db.SetSuppressions(t.Context(), "team-a", []database.NewSuppression{item}, "me"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	all := pendingEvents(t, db)
	if len(all) != writes {
		t.Fatalf("events = %d, want %d", len(all), writes)
	}
	byBefore := make(map[string]*database.Suppression)
	for _, e := range all {
		key := ""
		if e.Before != nil {
			key = e.Before.Detail
		}
		if _, exists := byBefore[key]; exists {
			t.Fatalf("concurrent update lost its real before-value: %q", key)
		}
		byBefore[key] = e.After
	}
	detail := ""
	for range writes {
		next, ok := byBefore[detail]
		if !ok {
			t.Fatalf("broken before/after chain at %q", detail)
		}
		detail = next.Detail
	}
	if stored := listSuppressions(t, db); len(stored) != 1 || stored[0].Detail != detail {
		t.Fatalf("final state does not match event chain: %+v", stored)
	}
	var delivered sync.Map
	for round := 0; round < writes && len(pendingEvents(t, db)) > 0; round++ {
		ready := make(chan struct{})
		var readers sync.WaitGroup
		readers.Add(2)
		for _, consumer := range []*database.DB{db, replica} {
			wg.Go(func() {
				batch, err := consumer.ListSuppressionEvents(t.Context(), 3)
				if err != nil {
					t.Error(err)
					readers.Done()
					return
				}
				if len(batch) == 0 || len(batch) > 3 {
					t.Errorf("bounded batch returned %d events", len(batch))
				}
				readers.Done()
				<-ready
				var ids []string
				for _, e := range batch {
					ids = append(ids, e.ID)
					delivered.Store(e.ID, true)
				}
				if err := consumer.AcknowledgeSuppressionEvents(t.Context(), ids); err != nil {
					t.Error(err)
				}
			})
		}
		readers.Wait()
		close(ready)
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}
	if len(pendingEvents(t, db)) != 0 {
		t.Fatal("consumers did not drain pending events")
	}
	for _, e := range all {
		if _, ok := delivered.Load(e.ID); !ok {
			t.Fatalf("event %s disappeared without delivery", e.ID)
		}
	}
}
