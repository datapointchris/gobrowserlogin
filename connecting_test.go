package gobrowserlogin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// An API starting while its session tables are not there yet still challenges
// a request with no session, and logs a browser in once Run gets through.
func TestConnecting_ChallengesARequestWithNoSessionUntilRunGetsThrough(t *testing.T) {
	p := newProvider(t, true)
	store := newMemoryStore()
	var tablesThere atomic.Bool
	c, err := NewConnecting(Config{
		Issuer:       p.issuer(),
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  testRedirectURL,
		Logger:       slog.New(slog.DiscardHandler),
	}, func(context.Context) (Store, error) {
		if !tablesThere.Load() {
			return nil, errors.New("the session tables are not there yet")
		}
		return store, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.firstRetry, c.lastRetry = time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Run(ctx)

	b := newBrowser()
	api := func() (Identity, error) {
		return c.Authenticate(b.request(http.MethodGet, "https://app.example/api/items", true))
	}
	if _, err := api(); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a request with no session, before Run gets through: %v", err)
	}
	b.cookies[sessionCookie] = "a session from before the restart"
	if _, err := api(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("a request with a session, before Run gets through: %v", err)
	}
	if resp := b.navigate(c.Login, "https://app.example/auth/login"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a login before Run gets through answered %d", resp.StatusCode)
	}

	tablesThere.Store(true)
	for deadline := time.Now().Add(5 * time.Second); c.Ready() != nil; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("Run did not get through: %v", c.Ready())
		}
	}
	delete(b.cookies, sessionCookie)
	login := b.navigate(c.Login, "https://app.example/auth/login?return_to=%2F")
	if resp := b.navigate(c.Callback, p.approve(login.Header.Get("Location"), "")); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback answered %d", resp.StatusCode)
	}
	if identity, err := api(); err != nil || identity.Subject != testSubject {
		t.Fatalf("after the login: %+v, %v", identity, err)
	}
}
