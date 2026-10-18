package postgresstore_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/datapointchris/gobrowserlogin"
	"github.com/datapointchris/gobrowserlogin/postgresstore"
)

// startPostgres runs a throwaway PostgreSQL and returns a database on it with
// no tables.
func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("app"), postgres.WithUsername("app"), postgres.WithPassword("app"),
		postgres.BasicWaitStrategies())
	testcontainers.CleanupContainer(t, container)
	if err != nil {
		t.Fatal(err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStore(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a PostgreSQL container")
	}
	ctx := context.Background()
	db := startPostgres(t)

	if _, err := postgresstore.New(ctx, db); err == nil {
		t.Fatal("New accepted a database without the schema")
	}
	if _, err := db.ExecContext(ctx, postgresstore.Schema); err != nil {
		t.Fatal(err)
	}
	store, err := postgresstore.New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	// PostgreSQL keeps microseconds.
	now := time.Now().Truncate(time.Microsecond)
	live, ended := gobrowserlogin.Key{1}, gobrowserlogin.Key{2}

	t.Run("a login attempt is taken once", func(t *testing.T) {
		attempt := gobrowserlogin.LoginAttempt{Nonce: "n", CodeVerifier: "v", ReturnTo: "/trips", ExpiresAt: now.Add(time.Minute)}
		if err := store.SaveLoginAttempt(ctx, live, attempt); err != nil {
			t.Fatal(err)
		}
		taken, err := store.TakeLoginAttempt(ctx, live)
		if err != nil || taken.Nonce != "n" || taken.CodeVerifier != "v" || taken.ReturnTo != "/trips" || !taken.ExpiresAt.Equal(attempt.ExpiresAt) {
			t.Fatalf("took %+v, %v", taken, err)
		}
		if _, err := store.TakeLoginAttempt(ctx, live); !errors.Is(err, gobrowserlogin.ErrNotFound) {
			t.Fatalf("a second take: %v", err)
		}
	})

	t.Run("a session is kept, touched and deleted", func(t *testing.T) {
		session := gobrowserlogin.Session{
			Identity:  gobrowserlogin.Identity{Subject: "user-1", Username: "chris", Groups: []string{"admins"}},
			CreatedAt: now, SeenAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if err := store.SaveSession(ctx, live, session); err != nil {
			t.Fatal(err)
		}
		later := now.Add(time.Minute)
		if err := store.TouchSession(ctx, live, later, later.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		loaded, err := store.LoadSession(ctx, live)
		if err != nil || loaded.Identity.Username != "chris" || !slices.Equal(loaded.Identity.Groups, []string{"admins"}) ||
			!loaded.CreatedAt.Equal(now) || !loaded.SeenAt.Equal(later) || !loaded.ExpiresAt.Equal(later.Add(time.Hour)) {
			t.Fatalf("loaded %+v, %v", loaded, err)
		}
		if err := store.DeleteSession(ctx, live); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadSession(ctx, live); !errors.Is(err, gobrowserlogin.ErrNotFound) {
			t.Fatalf("a deleted session: %v", err)
		}
	})

	t.Run("expired rows go and live ones stay", func(t *testing.T) {
		for key, expiresAt := range map[gobrowserlogin.Key]time.Time{live: now.Add(time.Minute), ended: now} {
			if err := store.SaveLoginAttempt(ctx, key, gobrowserlogin.LoginAttempt{ExpiresAt: expiresAt}); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveSession(ctx, key, gobrowserlogin.Session{CreatedAt: now, SeenAt: now, ExpiresAt: expiresAt}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.DeleteExpired(ctx, now); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadSession(ctx, ended); !errors.Is(err, gobrowserlogin.ErrNotFound) {
			t.Fatalf("an expired session: %v", err)
		}
		if _, err := store.TakeLoginAttempt(ctx, ended); !errors.Is(err, gobrowserlogin.ErrNotFound) {
			t.Fatalf("an expired attempt: %v", err)
		}
		if _, err := store.LoadSession(ctx, live); err != nil {
			t.Fatalf("a live session: %v", err)
		}
		if _, err := store.TakeLoginAttempt(ctx, live); err != nil {
			t.Fatalf("a live attempt: %v", err)
		}
	})
}
