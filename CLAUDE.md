# gobrowserlogin — Claude Code instructions

A public Go library, not a server. There is no `main` package and nothing to
install; it ships as git tags. Its consumers are Go web APIs that serve their
own single-page front end on one origin, and log its users in through an OIDC
provider. `goclilogin` is the same APIs' command-line half.

Written to be used by strangers. Treat the exported API, the README and the
godoc as the product. A change that suits the internal consumers is not
automatically right.

## Layout

| Path | Holds |
| --- | --- |
| `doc.go` | Package doc: why the session lives on the server |
| `config.go` | `Config`, its defaults and its validation |
| `sessions.go` | `Sessions`, `New`, `Authenticate`, `Logout`, the cookie policy, `CSRFHeader` |
| `login.go` | `Login`, the pushed authorization request, `return_to` checking |
| `callback.go` | `Callback`: the browser binding, the issuer check, redemption |
| `store.go` | `Store`, `Key`, `Session`, `LoginAttempt`, `Identity` |
| `postgresstore/` | The PostgreSQL `Store` and its `Schema` |
| `provider_test.go` | An in-process provider refusing what a real one refuses |

## Constraints that must not regress

- **No token reaches the browser, and none is kept.** The session holds the
  identity alone. Adding token storage is a design change with a README
  section to rewrite, not a field to add.
- **The callback checks the attempt cookie before it takes the attempt.** A
  forged callback, carrying another browser's state, must not consume the
  attempt it names. `TestCallback_RefusesAnAnswerThisBrowserDidNotAskFor` is
  the login-CSRF case.
- **Each attempt has its own cookie.** One shared name makes the second tab's
  login overwrite the first's.
  `TestCallback_KeepsTwoTabsLoggingInAtOnceApart` fails on that.
- **The CSRF header is checked before the store is read**, so a forged request
  costs no query. `Logout` checks it too and does nothing without it.
- **Every cookie keeps the `__Host-` requirements**: `Secure`, `Path=/`, no
  `Domain`. A deletion carries them as well, or a browser enforcing the prefix
  ignores it and the cookie survives logout.
- **The timeouts are checked against `Config` on every request**, never
  against the stored `ExpiresAt` alone. That field exists so a store can
  delete rows, and it holds whatever the configuration was at the last write.
- **The provider's client always has a deadline.** go-oidc fetches signing
  keys through the client's own `Timeout` and no context deadline, so a client
  without one is refused in `New`.
- **Each dependency earns its place.** This is the credential path, so an
  addition is classified by what it can reach, and what was accepted is written
  here.
  - `golang.org/x/oauth2` speaks the protocol.
  - `github.com/coreos/go-oidc` verifies ID tokens and reads discovery and
    userinfo.
  - `github.com/go-jose/go-jose` is go-oidc's, and the tests sign ID tokens
    with it.

  All three reach the network only through `Config.HTTPClient`, so they
  reach only the configured provider. The tests import two more.
  `testcontainers-go` drives the local Docker daemon, to run a throwaway
  PostgreSQL. `pgx` is the driver the tests open it with. Neither is compiled
  into a consumer.

## The PostgreSQL test needs Docker

`go test ./...` starts a PostgreSQL container for `postgresstore`. `-short`
skips it, which is what the commit hook runs. CI runs the whole suite on a
GitHub-hosted runner, which has Docker.

## Never write the breaking-change trailer in a commit message

Those two words anywhere in a message cut a major once this repo is past 0.x.
A major from v1 on, on a Go module with no `/vN` path, is an outage rather than
a version: consumers resolving `@latest` stop seeing the tag. On 0.x,
`allow-initial-development-versions` cuts them as a minor. The analyzer matches
unanchored, so a commit that merely *discusses* the trailer cuts one too — say
"that marker" instead.

This repo carries no `.semrelrc`. Reaching 1.0 is dropping
`allow-initial-development-versions`. A deliberate v2 needs a `.semrelrc`
mapping `chore(release-major)` to a major, and the same release adds `/v2` to
the module path.
