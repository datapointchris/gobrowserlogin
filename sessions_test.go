package gobrowserlogin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"testing"
	"time"
)

func newTestSessions(t *testing.T, p *provider) *Sessions {
	t.Helper()
	s, err := New(context.Background(), Config{
		Issuer:       p.issuer(),
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		RedirectURL:  testRedirectURL,
		Scopes:       []string{"openid", "profile", "groups"},
		Store:        newMemoryStore(),
		Logger:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// browser keeps cookies between requests the way a browser does, honoring a
// deletion.
type browser struct {
	cookies map[string]string
}

func newBrowser() *browser { return &browser{cookies: map[string]string{}} }

func (b *browser) request(method, target string, withCSRFHeader bool) *http.Request {
	req := httptest.NewRequest(method, target, http.NoBody)
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if withCSRFHeader {
		req.Header.Set(CSRFHeader, CSRFHeaderValue)
	}
	return req
}

func (b *browser) keep(resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		if cookie.MaxAge < 0 {
			delete(b.cookies, cookie.Name)
		} else {
			b.cookies[cookie.Name] = cookie.Value
		}
	}
}

func (b *browser) navigate(handler http.HandlerFunc, target string) *http.Response {
	rec := httptest.NewRecorder()
	handler(rec, b.request(http.MethodGet, target, false))
	resp := rec.Result()
	b.keep(resp)
	return resp
}

// startLogin goes to the login route and returns the authorization URL the
// browser is sent to.
func (b *browser) startLogin(t *testing.T, s *Sessions, returnTo string) string {
	t.Helper()
	resp := b.navigate(s.Login, "https://app.example/auth/login?return_to="+url.QueryEscape(returnTo))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login answered %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func (b *browser) authenticate(s *Sessions) (Identity, error) {
	return s.Authenticate(b.request(http.MethodGet, "https://app.example/api/items", true))
}

func TestLogin_EstablishesASessionTheAPIAuthenticates(t *testing.T) {
	for _, push := range []bool{true, false} {
		t.Run(map[bool]string{true: "pushed request", false: "request in the URL"}[push], func(t *testing.T) {
			p := newProvider(t, push)
			s := newTestSessions(t, p)
			b := newBrowser()

			resp := b.navigate(s.Callback, p.approve(b.startLogin(t, s, "/trips/5?view=map"), ""))
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/trips/5?view=map" {
				t.Fatalf("callback answered %d to %q", resp.StatusCode, resp.Header.Get("Location"))
			}
			var session *http.Cookie
			for _, cookie := range resp.Cookies() {
				if cookie.Name == sessionCookie {
					session = cookie
				}
			}
			if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode ||
				session.Path != "/" || session.Domain != "" {
				t.Fatalf("session cookie %+v", session)
			}
			if len(b.cookies) != 1 {
				t.Fatalf("the browser holds %v, where the login attempt's cookie should be gone", b.cookies)
			}

			identity, err := b.authenticate(s)
			if err != nil {
				t.Fatal(err)
			}
			if identity.Subject != testSubject || identity.Username != "chris" || !slices.Equal(identity.Groups, []string{"admins"}) {
				t.Fatalf("identity %+v", identity)
			}

			withoutHeader := b.request(http.MethodPost, "https://app.example/api/items", false)
			if _, err := s.Authenticate(withoutHeader); !errors.Is(err, ErrNoCSRFHeader) {
				t.Fatalf("a request without %s: %v", CSRFHeader, err)
			}
		})
	}
}

func TestCallback_RefusesAnAnswerThisBrowserDidNotAskFor(t *testing.T) {
	p := newProvider(t, true)
	s := newTestSessions(t, p)
	attacker, victim := newBrowser(), newBrowser()

	// Login CSRF: the attacker starts a login, and sends the victim's browser
	// to the callback with the attacker's code.
	callback := p.approve(attacker.startLogin(t, s, "/trips/5"), "")
	resp := victim.navigate(s.Callback, callback)
	if resp.StatusCode != http.StatusBadRequest || len(victim.cookies) != 0 {
		t.Fatalf("callback answered %d and set %v", resp.StatusCode, victim.cookies)
	}
	// The victim's browser read no attempt, so the attacker's path is not its to follow.
	if link := startAgainLink(t, resp); link != "/" {
		t.Fatalf("the refusal links to %q", link)
	}
}

// startAgainLink is where a refusal page's link goes, the step that works
// from a callback a reload would only refuse again.
func startAgainLink(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`<a href="([^"]*)">Start again</a>`).FindSubmatch(body)
	if match == nil {
		t.Fatalf("the refusal page carries no link: %s", body)
	}
	return string(match[1])
}

func TestCallback_CompletesEachAttemptOnce(t *testing.T) {
	p := newProvider(t, true)
	s := newTestSessions(t, p)
	b := newBrowser()
	location := b.startLogin(t, s, "/")
	attemptCookies := maps.Clone(b.cookies)
	callback := p.approve(location, "")
	b.navigate(s.Callback, callback)

	replay := newBrowser()
	replay.cookies = attemptCookies
	if resp := replay.navigate(s.Callback, callback); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a replayed callback answered %d", resp.StatusCode)
	}
}

func TestCallback_RefusesAnAnswerNotNamingThisIssuer(t *testing.T) {
	for name, issuer := range map[string]string{"another issuer": "https://elsewhere.example", "no issuer": "-"} {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t, true)
			s := newTestSessions(t, p)
			b := newBrowser()
			resp := b.navigate(s.Callback, p.approve(b.startLogin(t, s, "/trips/5"), issuer))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("callback answered %d", resp.StatusCode)
			}
			if link := startAgainLink(t, resp); link != "/trips/5" {
				t.Fatalf("the refusal links to %q, not the page the login started from", link)
			}
			if _, err := b.authenticate(s); !errors.Is(err, ErrNoSession) {
				t.Fatalf("authenticate: %v", err)
			}
		})
	}
}

func TestCallback_KeepsTwoTabsLoggingInAtOnceApart(t *testing.T) {
	p := newProvider(t, true)
	s := newTestSessions(t, p)
	b := newBrowser()
	first := p.approve(b.startLogin(t, s, "/first"), "")
	second := p.approve(b.startLogin(t, s, "/second"), "")

	for target, want := range map[string]string{second: "/second", first: "/first"} {
		if resp := b.navigate(s.Callback, target); resp.Header.Get("Location") != want {
			t.Fatalf("callback answered %d to %q, want %q", resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
}

func TestLogin_RefusesAReturnToOffThisSite(t *testing.T) {
	p := newProvider(t, true)
	s := newTestSessions(t, p)
	for _, returnTo := range []string{"https://evil.example/", "///evil.example/", `/\evil.example/`, "evil.example", "/\nSet-Cookie: x"} {
		resp := newBrowser().navigate(s.Login, "https://app.example/auth/login?return_to="+url.QueryEscape(returnTo))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("return_to %q answered %d", returnTo, resp.StatusCode)
		}
	}
}

func TestAuthenticate_EndsAnIdleOrOldSession(t *testing.T) {
	login := func(t *testing.T) (*Sessions, *browser, *time.Time) {
		p := newProvider(t, true)
		s := newTestSessions(t, p)
		clock := time.Now()
		s.now = func() time.Time { return clock }
		b := newBrowser()
		b.navigate(s.Callback, p.approve(b.startLogin(t, s, "/"), ""))
		return s, b, &clock
	}

	t.Run("idle", func(t *testing.T) {
		s, b, clock := login(t)
		*clock = clock.Add(DefaultIdleTimeout)
		if _, err := b.authenticate(s); !errors.Is(err, ErrNoSession) {
			t.Fatalf("after the idle timeout: %v", err)
		}
	})

	t.Run("in use", func(t *testing.T) {
		s, b, clock := login(t)
		for range 3 {
			*clock = clock.Add(DefaultIdleTimeout - time.Minute)
			if _, err := b.authenticate(s); err != nil {
				t.Fatalf("a session in use ended: %v", err)
			}
		}
	})

	t.Run("old", func(t *testing.T) {
		s, b, clock := login(t)
		loggedIn := *clock
		for *clock = loggedIn.Add(time.Hour); clock.Sub(loggedIn) < DefaultAbsoluteTimeout; *clock = clock.Add(time.Hour) {
			if _, err := b.authenticate(s); err != nil {
				t.Fatalf("a session in use ended %s after login: %v", clock.Sub(loggedIn), err)
			}
		}
		if _, err := b.authenticate(s); !errors.Is(err, ErrNoSession) {
			t.Fatalf("at the absolute timeout, in use hourly: %v", err)
		}
	})
}

func TestLogout_EndsTheSessionOnlyWithTheCSRFHeader(t *testing.T) {
	p := newProvider(t, true)
	s := newTestSessions(t, p)
	b := newBrowser()
	b.navigate(s.Callback, p.approve(b.startLogin(t, s, "/"), ""))

	forged := httptest.NewRecorder()
	if err := s.Logout(forged, b.request(http.MethodPost, "https://app.example/auth/logout", false)); !errors.Is(err, ErrNoCSRFHeader) {
		t.Fatalf("logout without the header: %v", err)
	}
	if _, err := b.authenticate(s); err != nil {
		t.Fatalf("a forged logout ended the session: %v", err)
	}

	ended := b.cookies[sessionCookie]
	rec := httptest.NewRecorder()
	if err := s.Logout(rec, b.request(http.MethodPost, "https://app.example/auth/logout", true)); err != nil {
		t.Fatal(err)
	}
	b.keep(rec.Result())
	if len(b.cookies) != 0 {
		t.Fatalf("the browser still holds %v", b.cookies)
	}
	// A copy of the cookie taken before logout names nothing after it.
	b.cookies[sessionCookie] = ended
	if _, err := b.authenticate(s); !errors.Is(err, ErrNoSession) {
		t.Fatalf("the ended session's cookie, presented again: %v", err)
	}
}
