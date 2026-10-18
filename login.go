package gobrowserlogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ReturnToParameter is the query parameter naming where Login sends the
// browser once the login completes: a path on this site, such as the page
// that got the 401. Absent means "/".
const ReturnToParameter = "return_to"

// pushResponseLimit bounds what is read of a pushed authorization response,
// which is a few hundred bytes of JSON.
const pushResponseLimit = 64 << 10

// Login starts a login and sends the browser to the provider. Serve it on GET,
// and send the browser to it with a navigation rather than a fetch, since it
// answers with a redirect off this site.
//
// The attempt is recorded in the Store under its OAuth state, with the nonce
// the ID token must carry back and the PKCE verifier the token request proves
// the code with. A cookie naming the state binds the attempt to this browser,
// so a callback carrying another browser's state is refused. Where the
// provider advertises RFC 9126 pushed authorization requests, the request
// travels to the provider directly, authenticated with the client secret, and
// the browser carries only a reference to it.
func (s *Sessions) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnTo, err := localPath(r.URL.Query().Get(ReturnToParameter))
	if err != nil {
		refuse(w, http.StatusBadRequest, err.Error())
		return
	}

	now := s.now()
	// Expired rows are deleted here rather than on a timer. A login is rare,
	// so the store stays small without the caller running anything.
	if err := s.cfg.Store.DeleteExpired(ctx, now); err != nil {
		s.cfg.Logger.WarnContext(ctx, "could not delete expired login attempts and sessions", "error", err)
	}

	state, nonce, verifier := newSecret(), newSecret(), oauth2.GenerateVerifier()
	attempt := LoginAttempt{Nonce: nonce, CodeVerifier: verifier, ReturnTo: returnTo, ExpiresAt: now.Add(attemptLifetime)}
	if err := s.cfg.Store.SaveLoginAttempt(ctx, keyOf(state), attempt); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "could not record a login attempt", "error", err)
		refuse(w, http.StatusServiceUnavailable, "The login could not start. Reload the page to try again.")
		return
	}

	target, err := s.authorizationURL(oidc.ClientContext(ctx, s.cfg.HTTPClient), state, nonce, verifier)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "could not start a login at the provider", "error", err)
		refuse(w, http.StatusBadGateway, "The login server did not accept the login. Reload the page to try again.")
		return
	}
	setCookie(w, attemptCookieName(state), state, attemptLifetime, http.SameSiteLaxMode)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// authorizationURL is where the browser goes to log in: a reference to a
// pushed request where the provider takes them, the whole request otherwise.
func (s *Sessions) authorizationURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	direct := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	if s.pushEndpoint == "" {
		return direct, nil
	}
	parsed, err := url.Parse(direct)
	if err != nil {
		return "", err
	}
	requestURI, err := s.push(ctx, parsed.Query())
	if err != nil {
		return "", err
	}
	reference := url.Values{"client_id": {s.oauth.ClientID}, "request_uri": {requestURI}}
	separator := "?"
	if strings.Contains(s.oauth.Endpoint.AuthURL, "?") {
		separator = "&"
	}
	return s.oauth.Endpoint.AuthURL + separator + reference.Encode(), nil
}

// push sends an authorization request to the provider's RFC 9126 endpoint and
// returns the request_uri the browser presents in its place. The client
// authenticates as it does at the token endpoint.
func (s *Sessions) push(ctx context.Context, request url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.pushEndpoint, strings.NewReader(request.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 § 2.3.1 form-encodes both halves before Basic encodes them,
	// as x/oauth2 does at the token endpoint.
	req.SetBasicAuth(url.QueryEscape(s.oauth.ClientID), url.QueryEscape(s.oauth.ClientSecret))

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("push the authorization request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, pushResponseLimit))
	if err != nil {
		return "", fmt.Errorf("read the pushed authorization response: %w", err)
	}

	var answer struct {
		RequestURI  string `json:"request_uri"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	decodeErr := json.Unmarshal(body, &answer)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		if decodeErr == nil && answer.Error != "" {
			return "", fmt.Errorf("the pushed authorization request was refused with %s: %s %s", resp.Status, answer.Error, answer.Description)
		}
		return "", fmt.Errorf("the pushed authorization request was refused with %s", resp.Status)
	}
	if decodeErr != nil {
		return "", fmt.Errorf("decode the pushed authorization response: %w", decodeErr)
	}
	if answer.RequestURI == "" {
		return "", errors.New("the pushed authorization response carries no request_uri")
	}
	return answer.RequestURI, nil
}

// localPath returns raw where it is a path on this site, and "/" where it is
// empty. Anything a browser could resolve to another host is refused, so no
// login link on this site can land its follower on another one.
func localPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	refused := fmt.Errorf("%s must be a path on this site, beginning with a single /", ReturnToParameter)
	// A browser reads a backslash as a slash, so /\host is //host to it. It
	// also reads ///host as //host, which url.Parse takes for a path.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "", refused
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", refused
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil {
		return "", refused
	}
	return raw, nil
}

// refuse answers a navigation the library could not complete. The browser
// shows the sentence, so it says what to do next, and the reason goes to the
// log instead.
func refuse(w http.ResponseWriter, status int, sentence string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, sentence, status)
}
