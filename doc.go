// Package gobrowserlogin logs a browser into a Go web API through an OIDC
// provider, with the API holding the session.
//
// It is the backend-for-frontend pattern of RFC 10017, the OAuth 2.0 best
// current practice for browser-based applications, for an API that serves its
// own single-page front end. The API is a confidential client of the provider.
// It runs the authorization code flow with PKCE, keeps the resulting session in
// a server-side store, and gives the browser nothing but an opaque cookie. No
// token ever reaches JavaScript, so script running in the page has nothing to
// steal and can act only while the page is open.
//
// The OAuth protocol is golang.org/x/oauth2's, and ID token verification is
// github.com/coreos/go-oidc's. This package adds what neither holds: the login
// attempt bound to the browser that started it, pushed authorization requests,
// the RFC 9207 issuer check, the session store with idle and absolute
// lifetimes, and the cookie and CSRF policy RFC 10017 sets.
//
// # Requests
//
// A request is authenticated by Sessions.Authenticate, which reads the session
// cookie and requires the static header CSRFHeader on every request carrying
// it. A cross-origin page cannot add that header without a CORS preflight the
// API never approves, so a forged request is refused even from a sibling
// subdomain, where SameSite does not apply. A navigation cannot carry the
// header either, so the front end's files and every route a browser navigates
// to are served without Authenticate.
package gobrowserlogin
