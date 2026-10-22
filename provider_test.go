package gobrowserlogin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testClientID = "app-web"
	// The slash and plus are form-encoded inside Basic auth, which a client
	// skipping RFC 6749 § 2.3.1's encoding gets wrong.
	testClientSecret = "s3cret/with+chars"
	testRedirectURL  = "https://app.example/auth/callback"
	testSubject      = "user-1"
)

var (
	signingKeyOnce sync.Once
	signingKey     *rsa.PrivateKey
)

func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	signingKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		signingKey = key
	})
	return signingKey
}

// provider is an OIDC provider that refuses what a real one refuses: a token
// request with the wrong client secret or PKCE verifier, a code used twice,
// and, where it takes pushed requests, a browser carrying the whole request.
// Like one behind a bot filter, it refuses Go's default User-Agent.
type provider struct {
	t      *testing.T
	server *httptest.Server
	push   bool

	mu      sync.Mutex
	pushed  map[string]url.Values
	grants  map[string]url.Values
	granted map[string]bool
}

func newProvider(t *testing.T, push bool) *provider {
	t.Helper()
	p := &provider{t: t, push: push, pushed: map[string]url.Values{}, grants: map[string]url.Values{}, granted: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.keys)
	mux.HandleFunc("POST /par", p.pushRequest)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("User-Agent"), "Go-http-client/") {
			http.Error(w, "refused by the bot filter", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *provider) issuer() string { return p.server.URL }

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	document := map[string]any{
		"issuer":                                         p.issuer(),
		"authorization_endpoint":                         p.issuer() + "/authorize",
		"token_endpoint":                                 p.issuer() + "/token",
		"userinfo_endpoint":                              p.issuer() + "/userinfo",
		"jwks_uri":                                       p.issuer() + "/jwks",
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}
	if p.push {
		document["pushed_authorization_request_endpoint"] = p.issuer() + "/par"
	}
	writeJSON(w, http.StatusOK, document)
}

func (p *provider) keys(w http.ResponseWriter, _ *http.Request) {
	key := jose.JSONWebKey{Key: &testSigningKey(p.t).PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
}

// authenticated reports whether the request carries this client's Basic
// credentials, each half form-decoded as RFC 6749 § 2.3.1 has them encoded.
func (p *provider) authenticated(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return false
	}
	id, idErr := url.QueryUnescape(id)
	secret, secretErr := url.QueryUnescape(secret)
	return idErr == nil && secretErr == nil && id == testClientID && secret == testClientSecret
}

func (p *provider) pushRequest(w http.ResponseWriter, r *http.Request) {
	if !p.authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	reference := "urn:ietf:params:oauth:request_uri:" + rand.Text()
	p.mu.Lock()
	p.pushed[reference] = r.PostForm
	p.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": reference, "expires_in": 60})
}

// approve plays the provider's login page: it reads the authorization request
// the browser was sent with and returns the callback URL the provider would
// send it back to. issuer replaces the iss parameter, and "-" leaves it out.
func (p *provider) approve(location, issuer string) string {
	p.t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		p.t.Fatalf("authorization URL %q: %v", location, err)
	}
	request := parsed.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	if reference := request.Get("request_uri"); reference != "" {
		pushed, ok := p.pushed[reference]
		if !ok {
			p.t.Fatalf("the browser carries request_uri %q, which was never pushed", reference)
		}
		delete(p.pushed, reference)
		request = pushed
	} else if p.push {
		p.t.Fatalf("the browser carries the whole request where the provider takes pushed ones: %s", location)
	}
	if request.Get("client_id") != testClientID || request.Get("redirect_uri") != testRedirectURL ||
		request.Get("response_type") != "code" || request.Get("code_challenge_method") != "S256" {
		p.t.Fatalf("authorization request %v", request)
	}

	code := rand.Text()
	p.grants[code] = request
	answer := url.Values{"code": {code}, "state": {request.Get("state")}}
	switch issuer {
	case "":
		answer.Set("iss", p.issuer())
	case "-":
	default:
		answer.Set("iss", issuer)
	}
	return testRedirectURL + "?" + answer.Encode()
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if !p.authenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	p.mu.Lock()
	request, ok := p.grants[r.PostForm.Get("code")]
	delete(p.grants, r.PostForm.Get("code"))
	p.mu.Unlock()
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != request.Get("redirect_uri") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != request.Get("code_challenge") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verifier"})
		return
	}

	now := time.Now()
	idToken := p.sign(map[string]any{
		"iss": p.issuer(), "sub": testSubject, "aud": testClientID,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": request.Get("nonce"),
	})
	accessToken := rand.Text()
	p.mu.Lock()
	p.granted[accessToken] = true
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (p *provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	ok := p.granted[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	p.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": testSubject, "preferred_username": "chris", "name": "Chris", "groups": []string{"admins"}})
}

func (p *provider) sign(claims map[string]any) string {
	p.t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: testSigningKey(p.t), KeyID: "test"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		p.t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		p.t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		p.t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return raw
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
