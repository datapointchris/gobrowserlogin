package gobrowserlogin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// ErrNotReady means a Connecting has not yet opened its Store and read the
// provider's discovery document. The API answers 503, because the browser's
// session may be sound and nothing can tell yet.
var ErrNotReady = errors.New("gobrowserlogin: the login has not opened its store and read the provider yet")

// errProviderRefusesClient marks a discovery document that rules this client
// out. Only a change at the provider mends it.
var errProviderRefusesClient = errors.New("the provider refuses this client")

// Connecting is a login that reads its provider in the background. New reads
// the discovery document once, so an API calling it at start cannot start
// while the provider is down. With a Connecting the API serves meanwhile: Run
// retries until it has built the Sessions, and only the requests that need
// the login wait.
//
// Until then Login and Callback answer a 503 page, and Logout returns
// ErrNotReady for a request holding a session. Authenticate returns
// ErrNotReady for a request presenting a session and the CSRF header. A
// request presenting no session is ErrNoSession as always, so an API that
// also takes bearer tokens still answers it with its challenge.
type Connecting struct {
	config                Config
	openStore             func(context.Context) (Store, error)
	firstRetry, lastRetry time.Duration

	sessions atomic.Pointer[Sessions]
	failure  atomic.Pointer[error]
}

// NewConnecting is a Connecting for cfg, which it checks as New does. cfg.Store
// stays nil, because Run calls openStore on each attempt. A store that checks
// its tables when it opens, as postgresstore.New does, is then retried along
// with the provider. Run starts it.
func NewConnecting(cfg Config, openStore func(context.Context) (Store, error)) (*Connecting, error) {
	switch {
	case cfg.Store != nil:
		return nil, errors.New("gobrowserlogin: Store is set, and a Connecting opens its own through openStore")
	case openStore == nil:
		return nil, errors.New("gobrowserlogin: openStore is nil")
	}
	r, err := cfg.resolve(true)
	if err != nil {
		return nil, err
	}
	return &Connecting{config: r.Config, openStore: openStore, firstRetry: time.Second, lastRetry: time.Minute}, nil
}

// Run builds the Sessions, retrying after each failure with a wait that
// doubles from a second to a minute, until it succeeds or ctx ends. It logs
// each failure to Config.Logger: at Error where the provider's discovery
// document rules this client out, and at Warn where a retry may mend it.
func (c *Connecting) Run(ctx context.Context) {
	log := c.config.Logger
	wait := c.firstRetry
	for {
		sessions, err := c.connect(ctx)
		switch {
		case err == nil:
			c.sessions.Store(sessions)
			log.InfoContext(ctx, "browser login ready", "issuer", c.config.Issuer, "client_id", c.config.ClientID, "redirect_url", c.config.RedirectURL)
			return
		case ctx.Err() != nil:
			return
		}
		c.failure.Store(&err)
		level := slog.LevelWarn
		if errors.Is(err, errProviderRefusesClient) {
			level = slog.LevelError
		}
		log.Log(ctx, level, "browser login not ready", "issuer", c.config.Issuer, "client_id", c.config.ClientID, "error", err, "retry_in", wait.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, c.lastRetry)
	}
}

func (c *Connecting) connect(ctx context.Context) (*Sessions, error) {
	store, err := c.openStore(ctx)
	if err != nil {
		return nil, fmt.Errorf("gobrowserlogin: open the store: %w", err)
	}
	cfg := c.config
	cfg.Store = store
	return New(ctx, cfg)
}

// Ready is nil once Run has built the Sessions. Before then it is ErrNotReady,
// wrapping the last reason Run could not.
func (c *Connecting) Ready() error {
	if c.sessions.Load() != nil {
		return nil
	}
	if failure := c.failure.Load(); failure != nil {
		return fmt.Errorf("%w: %w", ErrNotReady, *failure)
	}
	return ErrNotReady
}

// Authenticate is Sessions.Authenticate once Run has built the Sessions.
// Before then it returns ErrNoSession and ErrNoCSRFHeader as that does, and
// Ready's error for a request presenting a session and the header.
func (c *Connecting) Authenticate(r *http.Request) (Identity, error) {
	if s := c.sessions.Load(); s != nil {
		return s.Authenticate(r)
	}
	if _, err := presentedSession(r); err != nil {
		return Identity{}, err
	}
	return Identity{}, c.Ready()
}

// Login is Sessions.Login once Run has built the Sessions, and a 503 page
// before then.
func (c *Connecting) Login(w http.ResponseWriter, r *http.Request) {
	if s := c.sessions.Load(); s != nil {
		s.Login(w, r)
		return
	}
	refuseUntilReady(w)
}

// Callback is Sessions.Callback once Run has built the Sessions, and a 503
// page before then. The attempt stays in the store, so reloading the page
// once the login is ready completes it.
func (c *Connecting) Callback(w http.ResponseWriter, r *http.Request) {
	if s := c.sessions.Load(); s != nil {
		s.Callback(w, r)
		return
	}
	refuseUntilReady(w)
}

// Logout is Sessions.Logout once Run has built the Sessions. Before then it
// refuses a request without the CSRF header as that does, and treats one with
// no session as logged out. It returns Ready's error for one holding a
// session, and leaves the cookie in place.
func (c *Connecting) Logout(w http.ResponseWriter, r *http.Request) error {
	if s := c.sessions.Load(); s != nil {
		return s.Logout(w, r)
	}
	if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
		return ErrNoCSRFHeader
	}
	if _, err := presentedSession(r); err != nil {
		return nil
	}
	return c.Ready()
}

func refuseUntilReady(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	refuse(w, http.StatusServiceUnavailable, "Logging in is not available yet, because the identity provider has not been reached. Try again in a minute.", "")
}
