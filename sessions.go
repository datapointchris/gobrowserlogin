package gobrowserlogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// CSRFHeader is the header every request carrying the session cookie sends,
// with the value CSRFHeaderValue. A page on another origin cannot add a custom
// header without a CORS preflight, and an API that answers no preflight
// approves none, so the browser never sends the forged request. That holds
// for a sibling subdomain too, which is same-site and so passes SameSite.
// RFC 10017 § 6.1.3.3 leaves the name to the application.
const (
	CSRFHeader      = "X-CSRF"
	CSRFHeaderValue = "1"
)

const (
	// sessionCookie carries the session's secret. __Host- makes the browser
	// refuse it unless it is Secure, has Path=/ and names no Domain, so a
	// sibling subdomain cannot plant or overwrite it. Http- makes a browser
	// that knows the prefix refuse it from script as well.
	sessionCookie = "__Host-Http-session"

	// attemptCookiePrefix begins the cookie binding a login attempt to the
	// browser that started it. Each attempt has its own, so two tabs logging
	// in at once do not overwrite each other's.
	attemptCookiePrefix = "__Host-Http-login-"

	// attemptLifetime is how long a browser has to finish a login.
	attemptLifetime = 10 * time.Minute

	// touchInterval is how stale SeenAt may grow before a request writes it.
	// Writing it on every request would make every read a write.
	touchInterval = time.Minute
)

var (
	// ErrNoSession means the request carries no session cookie, or one
	// naming no live session. The API answers 401, and the front end sends
	// the browser to the login route.
	ErrNoSession = errors.New("gobrowserlogin: no session")

	// ErrNoCSRFHeader means the request carries the session cookie without
	// CSRFHeader. The API answers 403. A front end that sends the header on
	// every request never sees it, so it marks a forged request or a front
	// end missing the header.
	ErrNoCSRFHeader = errors.New("gobrowserlogin: the request carries the session cookie without the " + CSRFHeader + " header")
)

// Sessions logs browsers in through one provider and authenticates their
// requests. Mount Login, Callback and Logout as routes, and call Authenticate
// from the API's own authentication middleware.
type Sessions struct {
	cfg             resolved
	oauth           oauth2.Config
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	pushEndpoint    string
	issuerParameter bool
	now             func() time.Time
}

// providerMetadata is what the discovery document says beyond what go-oidc
// reads itself.
type providerMetadata struct {
	// PushEndpoint is RFC 9126's pushed authorization request endpoint. A
	// login uses it wherever it is advertised.
	PushEndpoint string `json:"pushed_authorization_request_endpoint"`

	// IssuerParameter is RFC 9207's promise that every authorization
	// response names its issuer. Where it is made, a response naming none is
	// refused.
	IssuerParameter bool `json:"authorization_response_iss_parameter_supported"`

	// TokenAuthMethods is RFC 8414's list. Absent means client_secret_basic
	// alone.
	TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
}

// New reads the provider's discovery document and returns the Sessions for
// cfg. It fails where the document cannot be read, or names an issuer other
// than cfg.Issuer.
func New(ctx context.Context, cfg Config) (*Sessions, error) {
	r, err := cfg.resolve()
	if err != nil {
		return nil, err
	}

	ctx = oidc.ClientContext(ctx, r.HTTPClient)
	provider, err := oidc.NewProvider(ctx, r.Issuer)
	if err != nil {
		return nil, fmt.Errorf("gobrowserlogin: discover %s: %w", r.Issuer, err)
	}
	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("gobrowserlogin: decode %s's discovery document: %w", r.Issuer, err)
	}
	if len(metadata.TokenAuthMethods) > 0 && !slices.Contains(metadata.TokenAuthMethods, "client_secret_basic") {
		return nil, fmt.Errorf("gobrowserlogin: %s does not accept client_secret_basic at its token endpoint, only %v", r.Issuer, metadata.TokenAuthMethods)
	}

	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return &Sessions{
		cfg: r,
		oauth: oauth2.Config{
			ClientID:     r.ClientID,
			ClientSecret: r.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  r.RedirectURL,
			Scopes:       r.scopes,
		},
		provider:        provider,
		verifier:        provider.Verifier(&oidc.Config{ClientID: r.ClientID}),
		pushEndpoint:    metadata.PushEndpoint,
		issuerParameter: metadata.IssuerParameter,
		now:             time.Now,
	}, nil
}

// Authenticate returns the identity of the session the request's cookie
// names. It returns ErrNoSession where there is none, and ErrNoCSRFHeader
// where the cookie arrives without CSRFHeader. Any other error is the store
// failing, which says nothing about the browser.
//
// A session unused for IdleTimeout, or older than AbsoluteTimeout, has ended.
// A request on a live session moves its idle deadline, writing the store at
// most once a minute.
func (s *Sessions) Authenticate(r *http.Request) (Identity, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return Identity{}, ErrNoSession
	}
	if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
		return Identity{}, ErrNoCSRFHeader
	}

	ctx := r.Context()
	key := keyOf(cookie.Value)
	session, err := s.cfg.Store.LoadSession(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return Identity{}, ErrNoSession
	}
	if err != nil {
		return Identity{}, fmt.Errorf("gobrowserlogin: load the session: %w", err)
	}

	now := s.now()
	if !now.Before(s.expiresAt(session.CreatedAt, session.SeenAt)) {
		if err := s.cfg.Store.DeleteSession(ctx, key); err != nil {
			s.cfg.Logger.WarnContext(ctx, "could not delete an ended session", "error", err)
		}
		return Identity{}, ErrNoSession
	}
	if now.Sub(session.SeenAt) >= touchInterval {
		// The request is authenticated whether or not this lands. A failed
		// write costs the session up to a minute of idle time.
		if err := s.cfg.Store.TouchSession(ctx, key, now, s.expiresAt(session.CreatedAt, now)); err != nil {
			s.cfg.Logger.WarnContext(ctx, "could not record a session's use", "error", err)
		}
	}
	return session.Identity, nil
}

// Logout ends the session the request's cookie names and clears the cookie.
// Serve it on POST. It returns ErrNoCSRFHeader where the header is missing,
// and does nothing then, so a cross-site form cannot log anyone out. A request
// with no session is already logged out and returns nil. The caller writes
// the response.
//
// It ends this API's session alone. The browser's session at the provider
// goes on, so the next login completes without asking the user anything.
func (s *Sessions) Logout(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
		return ErrNoCSRFHeader
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie.Value == "" {
		return nil
	}
	clearCookie(w, sessionCookie, http.SameSiteStrictMode)
	if err := s.cfg.Store.DeleteSession(r.Context(), keyOf(cookie.Value)); err != nil {
		return fmt.Errorf("gobrowserlogin: delete the session: %w", err)
	}
	return nil
}

// expiresAt is when a session created and last used at the given instants
// ends, under the configured timeouts.
func (s *Sessions) expiresAt(created, seen time.Time) time.Time {
	absolute := created.Add(s.cfg.AbsoluteTimeout)
	idle := seen.Add(s.cfg.IdleTimeout)
	if idle.Before(absolute) {
		return idle
	}
	return absolute
}

// newSecret is 128 random bits as text, for a state, a nonce or a session.
func newSecret() string {
	return rand.Text()
}

// attemptCookieName is the cookie binding the attempt with this state to its
// browser. It names a hash of the state, so the name never equals the value.
func attemptCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return attemptCookiePrefix + hex.EncodeToString(sum[:8])
}

// setCookie sets a cookie meeting the __Host- prefix's requirements.
func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})
}

// clearCookie deletes a cookie. The deletion carries the same attributes as
// the cookie, or a browser enforcing the prefix refuses it.
func clearCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})
}
