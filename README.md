# gobrowserlogin

OIDC login for the browser front end of a Go web API. The API is a
confidential client of the provider and keeps the session on the server. The
browser holds one opaque cookie, and no token ever reaches JavaScript.

This is the backend-for-frontend pattern of
[RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html), the OAuth best
current practice for browser-based applications. The RFC recommends it above
every other pattern for an application holding personal data, because script
running in the page has no token to steal. It can act only while the page is
open, through the same requests the page makes.

The OAuth protocol is `golang.org/x/oauth2`'s, and ID token verification is
`github.com/coreos/go-oidc`'s. This package adds what neither holds:

- the login attempt, bound to the browser that started it
- pushed authorization requests
- the RFC 9207 issuer check
- the session store, with idle and absolute lifetimes
- the cookie and CSRF policy RFC 10017 sets

It is a library with no `main` package.

## Install

```bash
go get github.com/datapointchris/gobrowserlogin@latest   # a tagged module; there is no binary
```

## Starting from scratch

An API serving its own single-page front end on one origin mounts three
routes and calls `Authenticate` from the middleware guarding its API routes:

```go
db := stdlib.OpenDBFromPool(pool) // any database/sql PostgreSQL driver
store, err := postgresstore.New(ctx, db) // refuses a database without postgresstore.Schema's tables

sessions, err := gobrowserlogin.New(ctx, gobrowserlogin.Config{
    Issuer:       "https://auth.example.com",
    ClientID:     "myapp-web",
    ClientSecret: os.Getenv("MYAPP_OIDC_CLIENT_SECRET"), // wherever the API keeps its secrets
    RedirectURL:  "https://myapp.example.com/api/auth/callback",
    Scopes:       []string{"openid", "profile", "groups"},
    Store:        store,
})

mux.HandleFunc("GET /api/auth/login", sessions.Login)       // a navigation, never a fetch
mux.HandleFunc("GET /api/auth/callback", sessions.Callback) // RedirectURL's path
mux.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
    switch err := sessions.Logout(w, r); {
    case errors.Is(err, gobrowserlogin.ErrNoCSRFHeader):
        w.WriteHeader(http.StatusForbidden)
    case err != nil:
        w.WriteHeader(http.StatusServiceUnavailable)
    default:
        w.WriteHeader(http.StatusNoContent)
    }
})

// in the middleware guarding the API's routes, which the front end's script calls
identity, err := sessions.Authenticate(r)
switch {
case errors.Is(err, gobrowserlogin.ErrNoSession):    // 401: the front end sends the browser to log in
case errors.Is(err, gobrowserlogin.ErrNoCSRFHeader): // 403: a forged request, or a front end missing the header
case err != nil:                                     // 503: the store failed
}
```

`Authenticate` authenticates a script's request, which carries the CSRF
header. A navigation cannot carry it. So the login and callback routes, the
front end's own files, and every route the browser navigates to sit outside
that middleware.

The same holds for anything a page loads by URL rather than by script. An
`<img src>`, a download link, an `EventSource` and a WebSocket upgrade each
send the session cookie without the header, and `Authenticate` refuses them
with `ErrNoCSRFHeader`. A resource that needs the session is read with
`fetch`, and the page shows it from there, through `URL.createObjectURL` for
an image or a download.

The front end sends the CSRF header on every request, and answers a 401 by
navigating to the login route with the page it was on:

```js
async function api(path, init = {}) {
  const resp = await fetch(path, { ...init, headers: { ...init.headers, 'X-CSRF': '1' } })
  if (resp.status === 401) {
    const here = location.pathname + location.search + location.hash
    location.assign('/api/auth/login?return_to=' + encodeURIComponent(here))
  }
  return resp
}
```

The provider needs the API registered as a confidential client:

- redirect URI exactly `RedirectURL`
- grant type `authorization_code`, response type `code`
- token endpoint authentication `client_secret_basic`
- PKCE with `S256`
- the scopes in `Config.Scopes`

Where the provider supports them, also require pushed authorization requests
for this client, and let a first-party client skip the consent screen.
Otherwise every login asks the user to approve their own application.

## Which function answers which question

| Ask | Function | Reads |
| --- | --- | --- |
| How does a browser log in | `Login`, then `Callback` | the provider's discovery document, its pushed request, token and userinfo endpoints, and the Store |
| Who sent this request | `Authenticate` | the session cookie, the CSRF header, and the Store |
| How does a browser log out | `Logout` | the session cookie, the CSRF header, and the Store |
| Where do sessions live | `Store`, `postgresstore.New` | PostgreSQL, through `database/sql` |
| What tables does that need | `postgresstore.Schema` | — |

## `Login` and `Callback` — a code completes one login, in the browser that asked for it

`Login` records the attempt in the Store under a hash of its OAuth state:

- the nonce the ID token must carry back
- the PKCE verifier
- the `return_to` path

It sets a cookie naming the state and sends the browser to the provider.
Each attempt has its own cookie, so two tabs logging in at once do not
overwrite each other's.

`Callback` refuses an answer whose state this browser holds no cookie for. A
code obtained in an attacker's browser therefore cannot log a victim's browser
in to the attacker's account. The attempt is deleted as it is read, so each
code completes one login at most. An attempt older than ten minutes is
refused.

`return_to` must be a path on this site. A full URL, `//host`, a backslash or a
control character is refused before anything is recorded. No login link on
this site can land its follower on another one.

**Pushed authorization requests.** Where the provider's discovery document
advertises an [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html)
endpoint, `Login` posts the authorization request there, authenticated with
the client secret. The browser carries only the reference it gets back. The
request's parameters never appear in the browser's history, and the provider
knows the request came from this client before any user sees it.

**Issuer check.** Where the provider promises
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) issuer identification,
`Callback` refuses an answer naming another issuer, or none. That closes the
mix-up attack, where an answer from one provider is passed off as another's.

**Redemption.** The code is redeemed with the client secret and the PKCE
verifier. The ID token's signature, issuer, audience, expiry and nonce are
checked. The identity is decoded from the ID token's claims and then from the
userinfo response, so a claim either one carries is kept. A userinfo
response naming another subject is refused.

A new session is created under a new secret, so a cookie planted before the
login names nothing after it. Where the provider shares this site, the browser
also sends the session it held, and that session is deleted.

**A refused answer links onward.** A refusal spends the attempt, and a reload
of the callback sends the same code again. So the refusal page links to the
attempt's `return_to` path, or to `/` where no attempt was read. The front end
there answers its next 401 by starting a new login.

## `Authenticate` — one cookie, one header, and nothing a script can read

The session cookie is `__Host-Http-session`:

- `Secure` and `HttpOnly`
- `SameSite=Strict`
- `Path=/`, with no `Domain`

That is what RFC 10017 § 6.1.3.2 asks for. `__Host-` makes the browser
refuse the cookie unless it carries those attributes, so a sibling subdomain
cannot plant or overwrite it. `Http-` makes a browser that knows the prefix
refuse it from script too. Its value is 128 random bits. The Store keys the
session by the value's SHA-256, so a copy of the store names no cookie anyone
could present.

**CSRF.** Every request carrying the cookie must also carry `X-CSRF: 1`
(`CSRFHeader`, `CSRFHeaderValue`). A page on another origin cannot add a
custom header without a CORS preflight. An API that answers no preflight
approves none, so the browser never sends the forged request. `SameSite=Strict`
alone falls short when the API shares its site with other applications, as
RFC 10017 § 6.1.3.3 notes: a sibling subdomain is same-site, and its requests
carry the cookie.

**Lifetimes.** A session ends after `IdleTimeout` with no request, two hours
by default. It also ends `AbsoluteTimeout` after its login however busy it
is, twelve hours by default. Both are checked against the configuration on
every request, so a shortened timeout reaches sessions already stored. A
request moves the idle deadline, writing the store at most once a minute.

The absolute timeout is what sends a user back to the provider. A user
disabled there keeps a session here until it runs out. Where the provider
still holds its own session, the next login completes without the user doing
anything.

## `Logout` — this API's session ends, and the provider's goes on

`Logout` deletes the session and clears the cookie. Serve it on POST. It
requires the CSRF header like any other request, so a cross-site form cannot
log anyone out. The response is the caller's to write.

It does not end the user's session at the provider. Where the provider still
holds one, the next login completes without asking anything. Ending that
session means sending the browser to the provider's own logout page.

## `postgresstore` — two tables, created by the application's migrations

`postgresstore.Schema` creates `browser_login_attempts` and
`browser_sessions`. Copy it into a migration. `postgresstore.New` checks both
tables and every column it uses, so a database missing them fails at startup
rather than at the first login.

`Login` deletes expired attempts and sessions each time it runs. A login is
rare, so the tables stay small without the application scheduling anything.

The store reaches PostgreSQL through `database/sql`. An application on pgx
shares its pool with `stdlib.OpenDBFromPool`.

## What it deliberately does not do

It keeps no tokens. The session holds the identity the provider stated at
login, and the access and refresh tokens are dropped once the userinfo
response is read. An API answering its own front end needs nothing else, and
a refresh token kept at rest is a credential nobody uses. The cost is that a
user disabled at the provider keeps a session here until its absolute timeout.
An API that calls another API on the user's behalf needs the tokens, and that
is the requirement that would add them.

It does not do RP-initiated, front-channel or back-channel logout. It does
not do DPoP or mTLS-bound tokens either. Each needs the tokens it does not
keep, or a provider capability not every provider has.

It is not a general OIDC client. [zitadel/oidc](https://github.com/zitadel/oidc)
is one, and is OpenID Foundation certified.
