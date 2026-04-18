package cmd

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/spf13/viper"

	"github.com/steipete/eightctl/internal/client"
	"github.com/steipete/eightctl/internal/tokencache"
)

func useTempKeyring(t *testing.T) func() {
	t.Helper()
	tmp := t.TempDir()
	opener := func() (keyring.Keyring, error) {
		return keyring.Open(keyring.Config{
			ServiceName:      "eightctl-test",
			AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
			FileDir:          filepath.Join(tmp, "keyring"),
			FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
		})
	}
	restore := tokencache.SetOpenKeyringForTest(opener)
	restoreFile := tokencache.SetOpenFileKeyringForTest(opener)
	t.Cleanup(restore)
	t.Cleanup(restoreFile)
	return restore
}

func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

func TestRequireAuthFieldsPassesWithCachedToken(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)

	// Save a cached token without setting credentials.
	cl := client.New("", "", "", "", "")
	if err := tokencache.Save(cl.Identity(), "tok", time.Now().Add(time.Hour), "cached-user"); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	if err := requireAuthFields(); err != nil {
		t.Fatalf("requireAuthFields should pass with cache: %v", err)
	}
	if got := viper.GetString("user_id"); got != "cached-user" {
		t.Fatalf("user_id not propagated from cache, got %q", got)
	}
}

func TestRequireAuthFieldsFailsWithoutCacheOrCreds(t *testing.T) {
	useTempKeyring(t)
	resetViper(t)

	err := requireAuthFields()
	if err == nil {
		t.Fatalf("expected missing credentials error")
	}
}
