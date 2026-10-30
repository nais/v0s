package database_test

import (
	"context"
	"testing"

	"github.com/nais/v0s/internal/database/databasetest"
)

func TestWithLock(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	ran, err := db.WithLock(ctx, "gc", func(ctx context.Context) error {
		tests := []struct {
			name    string
			lock    string
			wantRan bool
		}{
			{name: "same name is held", lock: "gc", wantRan: false},
			{name: "other name is free", lock: "enrich", wantRan: true},
		}
		for _, tt := range tests {
			ran, err := db.WithLock(ctx, tt.lock, func(context.Context) error { return nil })
			if err != nil {
				t.Fatalf("%s: %v", tt.name, err)
			}
			if ran != tt.wantRan {
				t.Errorf("%s: ran = %t, want %t", tt.name, ran, tt.wantRan)
			}
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("WithLock = %t, %v, want true, nil", ran, err)
	}

	ran, err = db.WithLock(ctx, "gc", func(context.Context) error { return nil })
	if err != nil || !ran {
		t.Errorf("WithLock after release = %t, %v, want true, nil", ran, err)
	}
}
