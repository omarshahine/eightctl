package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/steipete/eightctl/internal/tokencache"
)

// recordingAPI stands in for the Eight Sleep API, recording the bearer
// credential on every request and issuing a fresh token from its auth endpoint.
type recordingAPI struct {
	mu        sync.Mutex
	bearers   []string
	authCalls int
	newToken  string
}

func (a *recordingAPI) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/auth") {
			a.mu.Lock()
			a.authCalls++
			a.mu.Unlock()
			fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600,"userId":"uid"}`, a.newToken)
			return
		}
		a.mu.Lock()
		a.bearers = append(a.bearers, r.Header.Get("Authorization"))
		a.mu.Unlock()
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	prev := authURL
	authURL = srv.URL + "/auth"
	t.Cleanup(func() { authURL = prev })
	return srv
}

func (a *recordingAPI) sawBearer(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, got := range a.bearers {
		if got == "Bearer "+token {
			return true
		}
	}
	return false
}

func (a *recordingAPI) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.authCalls
}

func newSwitchClient(srv *httptest.Server) *Client {
	c := New("user@example.test", "pw", "", "cid", "secret")
	c.BaseURL = srv.URL
	c.AppURL = srv.URL
	return c
}

// Pinning storage to the file backend must not leave a usable session behind in
// the OS keyring. Asserting on tokencache.Load alone would not settle it: the
// question is what the production client puts on the wire afterwards.
func TestFreshClientDoesNotSendTokenRevokedWhilePinnedToFile(t *testing.T) {
	primary := keyring.NewArrayKeyring(nil)
	file := keyring.NewArrayKeyring(nil)
	defer tokencache.SetOpenKeyringForTest(func() (keyring.Keyring, error) { return primary, nil })()
	defer tokencache.SetOpenFileKeyringForTest(func() (keyring.Keyring, error) { return file, nil })()
	defer tokencache.SetFileBackendPinForTest(false)()

	const stale = "stale-token-must-not-be-sent"
	api := &recordingAPI{newToken: "fresh-token"}
	srv := api.start(t)
	ctx := context.Background()

	// A previous, unpinned run cached a token in the OS keyring.
	seed := newSwitchClient(srv)
	if err := tokencache.Save(seed.Identity(), stale, time.Now().Add(time.Hour), "uid"); err != nil {
		t.Fatalf("seeding primary backend: %v", err)
	}

	// Non-vacuity: before logout, a fresh client really does send that token.
	before := newSwitchClient(srv)
	if err := before.do(ctx, http.MethodGet, "/probe", nil, nil, nil); err != nil {
		t.Fatalf("pre-logout request: %v", err)
	}
	if !api.sawBearer(stale) {
		t.Fatal("setup is vacuous: the cached token was never sent before logout")
	}
	if api.calls() != 0 {
		t.Fatalf("pre-logout client should have used the cache, not re-authenticated (%d auth calls)", api.calls())
	}

	// This run is pinned to the file backend, as `keyring_backend: file` does.
	unpin := tokencache.SetFileBackendPinForTest(true)
	if err := tokencache.Clear(seed.Identity()); err != nil {
		t.Fatalf("logout while pinned to file: %v", err)
	}
	unpin()

	// A later unpinned run must re-authenticate, not resurrect the revoked token.
	after := newSwitchClient(srv)
	if err := after.do(ctx, http.MethodGet, "/probe", nil, nil, nil); err != nil {
		t.Fatalf("post-logout request: %v", err)
	}
	if len(api.bearers) < 2 {
		t.Fatalf("expected a post-logout request to reach the API, saw %d", len(api.bearers))
	}
	switch got := api.bearers[len(api.bearers)-1]; got {
	case "Bearer " + stale:
		t.Fatal("a fresh client sent the revoked token after logout across a backend switch")
	case "Bearer fresh-token":
		// Re-authenticated, as it must.
	default:
		t.Fatalf("post-logout request should carry a newly issued token, got %q", got)
	}
	if api.calls() != 1 {
		t.Fatalf("expected exactly one re-authentication after logout, got %d", api.calls())
	}
}
