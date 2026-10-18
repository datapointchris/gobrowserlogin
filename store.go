package gobrowserlogin

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

// Key names a stored login attempt or session. It is the SHA-256 of the
// secret the browser holds: the OAuth state for an attempt, the cookie's
// value for a session. A copy of a store therefore names nothing a reader
// could present as a browser.
type Key [sha256.Size]byte

func keyOf(secret string) Key {
	return sha256.Sum256([]byte(secret))
}

// ErrNotFound is what a Store returns for a key it does not hold.
var ErrNotFound = errors.New("gobrowserlogin: not in the store")

// Identity is who a session belongs to, as the provider stated at login. It
// is decoded from the ID token's claims and then the userinfo response's, so a
// claim either one carries is kept. A claim the granted scopes did not cover
// is empty.
type Identity struct {
	// Subject is the provider's stable identifier for the user.
	Subject string `json:"sub"`

	// Username is the preferred_username claim, from the profile scope.
	Username string `json:"preferred_username,omitempty"`

	// Name is the display name, from the profile scope.
	Name string `json:"name,omitempty"`

	// Groups is the groups claim, which most providers grant through a
	// groups scope.
	Groups []string `json:"groups,omitempty"`
}

// Session is one browser's login, as a Store keeps it.
type Session struct {
	Identity Identity

	// CreatedAt is when the login completed. The absolute timeout runs from
	// it.
	CreatedAt time.Time

	// SeenAt is when a request last used the session, to within a minute.
	// The idle timeout runs from it.
	SeenAt time.Time

	// ExpiresAt is the earlier of the two timeouts, as configured when the
	// session was last written. A store may delete the session after it.
	// Sessions checks both timeouts against its own configuration on every
	// request, so a shortened timeout applies to sessions already stored.
	ExpiresAt time.Time
}

// LoginAttempt is a login a browser has started and not finished.
type LoginAttempt struct {
	// Nonce is the value the ID token must carry back.
	Nonce string

	// CodeVerifier is the PKCE secret the token request proves the code
	// with.
	CodeVerifier string

	// ReturnTo is the path on this site the browser goes to after login.
	ReturnTo string

	// ExpiresAt is ten minutes after the attempt began.
	ExpiresAt time.Time
}

// Store keeps login attempts and sessions on the server, where script in the
// page cannot reach them. postgresstore is the implementation for PostgreSQL.
// Every method is called concurrently.
type Store interface {
	// SaveLoginAttempt records an attempt under a key no other attempt
	// holds.
	SaveLoginAttempt(ctx context.Context, key Key, attempt LoginAttempt) error

	// TakeLoginAttempt returns the attempt and deletes it in one step, so an
	// attempt completes one login at most. It returns ErrNotFound where key
	// holds none.
	TakeLoginAttempt(ctx context.Context, key Key) (LoginAttempt, error)

	// SaveSession records a session under a key no other session holds.
	SaveSession(ctx context.Context, key Key, session Session) error

	// LoadSession returns ErrNotFound where key holds none.
	LoadSession(ctx context.Context, key Key) (Session, error)

	// TouchSession sets a session's SeenAt and ExpiresAt. A key holding none
	// is not an error.
	TouchSession(ctx context.Context, key Key, seenAt, expiresAt time.Time) error

	// DeleteSession removes a session. A key holding none is not an error.
	DeleteSession(ctx context.Context, key Key) error

	// DeleteExpired removes every attempt and session whose ExpiresAt is not
	// after now.
	DeleteExpired(ctx context.Context, now time.Time) error
}
