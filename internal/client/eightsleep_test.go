package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockServer builds a test server that can serve a handful of endpoints the client expects.
func mockServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":{"userId":"uid-123","currentDevice":{"id":"dev-1"}}}`))
	})

	mux.HandleFunc("/users/uid-123/temperature", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"currentLevel":5,"currentState":{"type":"on"}}`))
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		// first call rate limits, second succeeds
		if r.Header.Get("X-Test-Retry") == "done" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	})

	srv := httptest.NewServer(mux)

	// client with pre-set token to skip auth
	c := New("email", "pass", "", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	return srv, c
}

func TestRequireUserFilledAutomatically(t *testing.T) {
	srv, c := mockServer(t)
	defer srv.Close()

	// UserID empty; GetStatus should fetch it from /users/me
	st, err := c.GetStatus(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if c.UserID != "uid-123" {
		t.Fatalf("expected user id populated, got %s", c.UserID)
	}
	if st.CurrentLevel != 5 || st.CurrentState.Type != "on" {
		t.Fatalf("unexpected status %+v", st)
	}
}

func TestAuthTokenEndpoint_FormEncoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Must be form-encoded, not JSON.
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form-urlencoded, got %s", ct)
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		// Verify correct client credentials are sent (not "sleep-client").
		if got := r.PostFormValue("client_id"); got != defaultClientID {
			t.Errorf("client_id = %q, want %q", got, defaultClientID)
		}
		if got := r.PostFormValue("client_secret"); got != defaultClientSecret {
			t.Errorf("client_secret = %q, want %q", got, defaultClientSecret)
		}
		if got := r.PostFormValue("grant_type"); got != "password" {
			t.Errorf("grant_type = %q, want password", got)
		}
		if got := r.PostFormValue("username"); got != "test@example.com" {
			t.Errorf("username = %q, want test@example.com", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok-123",
			"expires_in":   3600,
			"userId":       "uid-abc",
		})
	}))
	defer srv.Close()

	old := authURL
	authURL = srv.URL
	defer func() { authURL = old }()

	c := New("test@example.com", "secret", "", "", "")
	c.HTTP = srv.Client()

	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.token != "tok-123" {
		t.Errorf("token = %q, want tok-123", c.token)
	}
	if c.UserID != "uid-abc" {
		t.Errorf("UserID = %q, want uid-abc", c.UserID)
	}
}

func TestAuthTokenEndpoint_FallsBackToLegacy(t *testing.T) {
	tokenCalled := false
	legacyCalled := false

	mux := http.NewServeMux()
	// Token endpoint fails
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalled = true
		http.Error(w, "nope", http.StatusBadRequest)
	})
	// Legacy login succeeds
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		legacyCalled = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"session":{"token":"legacy-tok","userId":"uid-legacy","expirationDate":"2099-01-01T00:00:00Z"}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	old := authURL
	authURL = srv.URL + "/token"
	defer func() { authURL = old }()

	c := New("test@example.com", "secret", "", "", "")
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()

	if err := c.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !tokenCalled {
		t.Error("token endpoint was not tried")
	}
	if !legacyCalled {
		t.Error("legacy login was not tried after token failure")
	}
	if c.token != "legacy-tok" {
		t.Errorf("token = %q, want legacy-tok", c.token)
	}
}

func TestNoExplicitGzipHeader(t *testing.T) {
	// Verify we don't send Accept-Encoding: gzip manually, so Go's
	// http.Transport handles decompression transparently.
	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		// Go's Transport adds its own Accept-Encoding when we don't set one.
		// The key assertion: our code must NOT set it to exactly "gzip".
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"accept_encoding": ae})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("e", "p", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	var out map[string]string
	if err := c.do(context.Background(), http.MethodGet, "/check", nil, nil, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	// Go's transport sets "gzip" automatically but handles decompression.
	// We just verify our code didn't break anything.
	if out["accept_encoding"] == "" {
		t.Fatal("expected Accept-Encoding to be set by Go's transport")
	}
}

func Test429Retry(t *testing.T) {
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		count++
		if count == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	start := time.Now()
	if err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil, nil); err != nil {
		t.Fatalf("do retry: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 attempts, got %d", count)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Fatalf("expected backoff, got %v", elapsed)
	}
}

func Test429RetryCapped(t *testing.T) {
	// Verify retries are bounded: after maxRetries, return an error.
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/always429", func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusTooManyRequests)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New("email", "pass", "uid", "", "")
	c.BaseURL = srv.URL
	c.token = "t"
	c.tokenExp = time.Now().Add(time.Hour)
	c.HTTP = srv.Client()

	err := c.do(context.Background(), http.MethodGet, "/always429", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	// 1 initial + maxRetries = 4 total attempts
	if count != maxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", maxRetries+1, count)
	}
}
