package gobrowserlogin

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// DefaultScopes are what a login asks for when Config.Scopes is empty. openid
// makes it an OIDC login, and profile yields the username and display name an
// Identity carries.
var DefaultScopes = []string{"openid", "profile"}

const (
	// DefaultIdleTimeout ends a session no request has used for two hours.
	DefaultIdleTimeout = 2 * time.Hour

	// DefaultAbsoluteTimeout ends a session twelve hours after its login,
	// however busy it is. A login after that goes back to the provider, which
	// is what notices a user who was disabled there.
	DefaultAbsoluteTimeout = 12 * time.Hour

	// defaultProviderTimeout bounds each request to the provider made through
	// the default client.
	defaultProviderTimeout = 10 * time.Second
)

// Config is one web API's login for its browser front end, at one provider.
// Issuer, ClientID, ClientSecret, RedirectURL and Store are required. Every
// other field has a documented default.
type Config struct {
	// Issuer is the OIDC provider's base URL. Discovery hangs off it.
	Issuer string

	// ClientID and ClientSecret are the API's registration at the provider,
	// as a confidential client authenticating with HTTP Basic
	// (client_secret_basic). RFC 10017 § 6.1.3.1 requires a confidential
	// client: the secret is what stops anyone else redeeming a code issued
	// to this API.
	ClientID     string
	ClientSecret string

	// RedirectURL is where the provider sends the browser after login, and
	// where Sessions.Callback is served. It must be registered at the
	// provider exactly. It is https, or http on a loopback host, which
	// browsers treat as secure and keep secure cookies for.
	RedirectURL string

	// Scopes are requested at login. Empty means DefaultScopes. openid is
	// required. Add groups where the provider has that scope and the API
	// reads Identity.Groups.
	Scopes []string

	// Store keeps login attempts and sessions.
	Store Store

	// IdleTimeout ends a session no request has used for this long. Zero
	// means DefaultIdleTimeout.
	IdleTimeout time.Duration

	// AbsoluteTimeout ends a session this long after its login. Zero means
	// DefaultAbsoluteTimeout. It is also the session cookie's lifetime.
	AbsoluteTimeout time.Duration

	// HTTPClient makes every request to the provider. Nil means a client
	// with a ten-second timeout. A client with no Timeout is refused,
	// because go-oidc fetches the provider's signing keys under no other
	// deadline. A provider behind a bot filter may refuse Go's default
	// User-Agent, which the client's Transport can replace.
	HTTPClient *http.Client

	// Logger receives each refused login with its reason, which the browser
	// is not shown. Nil means slog.Default().
	Logger *slog.Logger
}

// resolved is a Config with its defaults applied and its fields checked.
type resolved struct {
	Config
	scopes []string
}

func (c Config) resolve() (resolved, error) {
	var problems []error
	if err := secureURL("Issuer", c.Issuer); err != nil {
		problems = append(problems, err)
	}
	if c.ClientID == "" {
		problems = append(problems, errors.New("ClientID is empty"))
	}
	if c.ClientSecret == "" {
		problems = append(problems, errors.New("ClientSecret is empty, and RFC 10017 requires a confidential client"))
	}
	if err := secureURL("RedirectURL", c.RedirectURL); err != nil {
		problems = append(problems, err)
	}
	if c.Store == nil {
		problems = append(problems, errors.New("Store is nil"))
	}
	if c.IdleTimeout < 0 || c.AbsoluteTimeout < 0 {
		problems = append(problems, errors.New("IdleTimeout and AbsoluteTimeout cannot be negative"))
	}
	if c.HTTPClient != nil && c.HTTPClient.Timeout <= 0 {
		problems = append(problems, errors.New("HTTPClient has no Timeout, so a provider that never answers would hold a login, and a key fetch, forever"))
	}

	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	if !slices.Contains(scopes, "openid") {
		problems = append(problems, errors.New("openid is not among the Scopes, so the provider would issue no ID token"))
	}
	if len(problems) > 0 {
		return resolved{}, fmt.Errorf("gobrowserlogin: %w", errors.Join(problems...))
	}

	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.AbsoluteTimeout == 0 {
		c.AbsoluteTimeout = DefaultAbsoluteTimeout
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: defaultProviderTimeout}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return resolved{Config: c, scopes: scopes}, nil
}

// secureURL refuses an address that is not absolute https, or http on a
// loopback host.
func secureURL(field, raw string) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return fmt.Errorf("%s is empty", field)
	case err != nil:
		return fmt.Errorf("%s: %w", field, err)
	case u.Host == "":
		return fmt.Errorf("%s %q is not an absolute URL", field, raw)
	case u.Fragment != "":
		return fmt.Errorf("%s %q carries a fragment", field, raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("%s %q is neither https nor http on a loopback host", field, raw)
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
