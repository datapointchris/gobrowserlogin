package gobrowserlogin

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Callback completes a login. Serve it on GET at Config.RedirectURL's path.
//
// It refuses an answer whose state this browser holds no cookie for, so a
// code obtained in one browser cannot log another one in. The attempt is
// deleted as it is read, so each code completes one login at most. Where the
// provider promises RFC 9207 issuer identification, an answer naming another
// issuer, or none, is refused. The code is redeemed with the client secret
// and the PKCE verifier, the ID token's signature, audience, expiry and nonce
// are checked, and the userinfo response must name the same subject.
//
// A new session is created under a new secret, so a cookie planted before the
// login names nothing after it. Where the provider shares this site, the
// browser also sends the session it held, and that session is deleted. The
// browser then goes to the attempt's return_to path.
//
// A refused answer cannot be retried: the attempt is spent, and a reload
// sends the same code again. The refusal page links to the attempt's
// return_to path instead, or to / where no attempt was read. The front end
// there answers its next 401 by starting a new login.
func (s *Sessions) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	query := r.URL.Query()
	again := "/"

	state := query.Get("state")
	if state == "" {
		s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the callback carries no state")
		refuse(w, http.StatusBadRequest, "The login server's answer is incomplete.", again)
		return
	}
	name := attemptCookieName(state)
	cookie, err := r.Cookie(name)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the browser holds no cookie for this state")
		refuse(w, http.StatusBadRequest, "This login was not started in this browser, or took longer than ten minutes.", again)
		return
	}
	clearCookie(w, name, http.SameSiteLaxMode)

	attempt, err := s.cfg.Store.TakeLoginAttempt(ctx, keyOf(state))
	if errors.Is(err, ErrNotFound) {
		s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the attempt was already used or has expired")
		refuse(w, http.StatusBadRequest, "This login was already completed or has expired.", again)
		return
	}
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "could not read a login attempt", "error", err)
		refuse(w, http.StatusServiceUnavailable, "The login could not be completed.", again)
		return
	}
	again = attempt.ReturnTo
	now := s.now()
	if !now.Before(attempt.ExpiresAt) {
		s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the attempt expired")
		refuse(w, http.StatusBadRequest, "This login took longer than ten minutes.", again)
		return
	}

	// RFC 9207: an answer from a provider other than the one this attempt
	// was sent to is a mix-up attack, whatever else it carries.
	if issuer := query.Get("iss"); issuer != "" || s.issuerParameter {
		if issuer != s.cfg.Issuer {
			s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the answer names another issuer", "iss", issuer)
			refuse(w, http.StatusBadRequest, "The answer did not come from this site's login server.", again)
			return
		}
	}
	if code := query.Get("error"); code != "" {
		s.cfg.Logger.WarnContext(ctx, "login refused by the provider", "error", code, "description", query.Get("error_description"))
		status := http.StatusBadGateway
		if code == "access_denied" {
			status = http.StatusForbidden
		}
		refuse(w, status, "The login server refused the login ("+code+").", again)
		return
	}
	code := query.Get("code")
	if code == "" {
		s.cfg.Logger.WarnContext(ctx, "login refused", "reason", "the callback carries no code")
		refuse(w, http.StatusBadRequest, "The login server's answer is incomplete.", again)
		return
	}

	identity, err := s.redeem(oidc.ClientContext(ctx, s.cfg.HTTPClient), code, attempt)
	if err != nil {
		s.cfg.Logger.ErrorContext(ctx, "login refused", "reason", err)
		refuse(w, http.StatusBadGateway, "The login could not be completed with the login server.", again)
		return
	}

	if held, err := r.Cookie(sessionCookie); err == nil && held.Value != "" {
		if err := s.cfg.Store.DeleteSession(ctx, keyOf(held.Value)); err != nil {
			s.cfg.Logger.WarnContext(ctx, "could not delete the session a login replaced", "error", err)
		}
	}
	secret := newSecret()
	session := Session{Identity: identity, CreatedAt: now, SeenAt: now, ExpiresAt: s.expiresAt(now, now)}
	if err := s.cfg.Store.SaveSession(ctx, keyOf(secret), session); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "could not record a session", "error", err)
		refuse(w, http.StatusServiceUnavailable, "The login could not be completed.", again)
		return
	}
	setCookie(w, sessionCookie, secret, s.cfg.AbsoluteTimeout, http.SameSiteStrictMode)
	w.Header().Set("Cache-Control", "no-store")
	// The callback's URL carries the code, which no later request needs to
	// name as its referrer.
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, attempt.ReturnTo, http.StatusSeeOther)
}

// redeem exchanges the code for tokens and returns who they say logged in.
// ctx carries the provider's HTTP client.
func (s *Sessions) redeem(ctx context.Context, code string, attempt LoginAttempt) (Identity, error) {
	token, err := s.oauth.Exchange(ctx, code, oauth2.VerifierOption(attempt.CodeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("redeem the code: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errors.New("the token response carries no ID token")
	}
	idToken, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify the ID token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(attempt.Nonce)) != 1 {
		return Identity{}, errors.New("the ID token carries another login's nonce")
	}

	var identity Identity
	if err := idToken.Claims(&identity); err != nil {
		return Identity{}, fmt.Errorf("decode the ID token's claims: %w", err)
	}
	if s.provider.UserInfoEndpoint() != "" {
		info, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return Identity{}, fmt.Errorf("read userinfo: %w", err)
		}
		// OIDC Core § 5.3.4: a userinfo response for another subject is
		// someone else's, and none of it may be used.
		if info.Subject != idToken.Subject {
			return Identity{}, fmt.Errorf("userinfo names subject %q where the ID token names %q", info.Subject, idToken.Subject)
		}
		if err := info.Claims(&identity); err != nil {
			return Identity{}, fmt.Errorf("decode userinfo: %w", err)
		}
	}
	identity.Subject = idToken.Subject
	return identity, nil
}
