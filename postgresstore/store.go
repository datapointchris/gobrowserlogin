// Package postgresstore keeps gobrowserlogin's login attempts and sessions in
// PostgreSQL, through database/sql and whichever driver the application
// already uses.
//
// The tables are Schema, which the application applies through its own
// migrations. New checks they are there, so a database missing them fails at
// startup rather than at the first login.
package postgresstore

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/datapointchris/gobrowserlogin"
)

// Schema creates the two tables a Store reads and writes.
//
//go:embed schema.sql
var Schema string

// Store is a gobrowserlogin.Store in PostgreSQL.
type Store struct {
	db *sql.DB
}

var _ gobrowserlogin.Store = (*Store)(nil)

// New returns a Store over db, after checking that Schema's tables and columns
// are there. db reaches PostgreSQL through any database/sql driver: pgx's
// stdlib.OpenDBFromPool shares an application's pgxpool.
func New(ctx context.Context, db *sql.DB) (*Store, error) {
	probes := []string{
		`SELECT state_sha256, nonce, code_verifier, return_to, expires_at FROM browser_login_attempts WHERE false`,
		`SELECT cookie_sha256, identity, created_at, seen_at, expires_at FROM browser_sessions WHERE false`,
	}
	for _, probe := range probes {
		if _, err := db.ExecContext(ctx, probe); err != nil {
			return nil, fmt.Errorf("postgresstore: the database lacks postgresstore.Schema's tables, which the application's migrations create: %w", err)
		}
	}
	return &Store{db: db}, nil
}

// SaveLoginAttempt implements gobrowserlogin.Store.
func (s *Store) SaveLoginAttempt(ctx context.Context, key gobrowserlogin.Key, attempt gobrowserlogin.LoginAttempt) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO browser_login_attempts (state_sha256, nonce, code_verifier, return_to, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		key[:], attempt.Nonce, attempt.CodeVerifier, attempt.ReturnTo, attempt.ExpiresAt)
	if err != nil {
		return fmt.Errorf("postgresstore: save a login attempt: %w", err)
	}
	return nil
}

// TakeLoginAttempt implements gobrowserlogin.Store. The row is deleted by the
// statement that returns it, so two callbacks racing on one attempt cannot
// both read it.
func (s *Store) TakeLoginAttempt(ctx context.Context, key gobrowserlogin.Key) (gobrowserlogin.LoginAttempt, error) {
	var attempt gobrowserlogin.LoginAttempt
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM browser_login_attempts WHERE state_sha256 = $1 RETURNING nonce, code_verifier, return_to, expires_at`,
		key[:]).Scan(&attempt.Nonce, &attempt.CodeVerifier, &attempt.ReturnTo, &attempt.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return gobrowserlogin.LoginAttempt{}, gobrowserlogin.ErrNotFound
	}
	if err != nil {
		return gobrowserlogin.LoginAttempt{}, fmt.Errorf("postgresstore: take a login attempt: %w", err)
	}
	return attempt, nil
}

// SaveSession implements gobrowserlogin.Store.
func (s *Store) SaveSession(ctx context.Context, key gobrowserlogin.Key, session gobrowserlogin.Session) error {
	identity, err := json.Marshal(session.Identity)
	if err != nil {
		return fmt.Errorf("postgresstore: encode an identity: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO browser_sessions (cookie_sha256, identity, created_at, seen_at, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		key[:], string(identity), session.CreatedAt, session.SeenAt, session.ExpiresAt)
	if err != nil {
		return fmt.Errorf("postgresstore: save a session: %w", err)
	}
	return nil
}

// LoadSession implements gobrowserlogin.Store.
func (s *Store) LoadSession(ctx context.Context, key gobrowserlogin.Key) (gobrowserlogin.Session, error) {
	var (
		session  gobrowserlogin.Session
		identity []byte
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT identity, created_at, seen_at, expires_at FROM browser_sessions WHERE cookie_sha256 = $1`,
		key[:]).Scan(&identity, &session.CreatedAt, &session.SeenAt, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return gobrowserlogin.Session{}, gobrowserlogin.ErrNotFound
	}
	if err != nil {
		return gobrowserlogin.Session{}, fmt.Errorf("postgresstore: load a session: %w", err)
	}
	if err := json.Unmarshal(identity, &session.Identity); err != nil {
		return gobrowserlogin.Session{}, fmt.Errorf("postgresstore: decode a session's identity: %w", err)
	}
	return session, nil
}

// TouchSession implements gobrowserlogin.Store.
func (s *Store) TouchSession(ctx context.Context, key gobrowserlogin.Key, seenAt, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE browser_sessions SET seen_at = $2, expires_at = $3 WHERE cookie_sha256 = $1`,
		key[:], seenAt, expiresAt)
	if err != nil {
		return fmt.Errorf("postgresstore: touch a session: %w", err)
	}
	return nil
}

// DeleteSession implements gobrowserlogin.Store.
func (s *Store) DeleteSession(ctx context.Context, key gobrowserlogin.Key) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM browser_sessions WHERE cookie_sha256 = $1`, key[:]); err != nil {
		return fmt.Errorf("postgresstore: delete a session: %w", err)
	}
	return nil
}

// DeleteExpired implements gobrowserlogin.Store.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) error {
	for _, statement := range []string{
		`DELETE FROM browser_login_attempts WHERE expires_at <= $1`,
		`DELETE FROM browser_sessions WHERE expires_at <= $1`,
	} {
		if _, err := s.db.ExecContext(ctx, statement, now); err != nil {
			return fmt.Errorf("postgresstore: delete expired rows: %w", err)
		}
	}
	return nil
}
