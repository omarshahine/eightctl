package tokencache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/log/v2"
	"github.com/99designs/keyring"
)

const (
	serviceName        = "eightctl"
	tokenKey           = "oauth-token"
	storageKeyV2Prefix = tokenKey + "_v2_"
)

type CachedToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    string    `json:"user_id,omitempty"`
}

// Identity describes the authentication context a token belongs to.
// Tokens are namespaced by base URL, client ID, and email so switching
// between accounts or environments doesn't reuse the wrong credentials.
type Identity struct {
	BaseURL  string
	ClientID string
	Email    string
}

var (
	openKeyring     = defaultOpenKeyring
	openFileKeyring = defaultOpenFileKeyring
	// pinFileBackend routes Save/Load to the file backend only. See UseFileBackend.
	pinFileBackend bool
)

// UseFileBackend pins reads and writes to the file backend, so the OS keyring
// is never opened for Save or Load.
//
// On macOS the keyring backend is the Keychain, and a Keychain item's ACL is
// bound to the code identity that created it. Any rebuild or reinstall of this
// binary therefore invalidates it, and every later command blocks on a consent
// dialog. On a headless or unattended host nobody sees that dialog, so it is
// indistinguishable from a hang: the process simply never returns, and any
// scheduler calling eightctl stalls until its own timeout.
//
// The file backend has no such binding and survives reinstalls untouched.
//
// This deliberately sets a flag rather than reassigning openKeyring. Clear()
// must keep reaching the real OS keyring whatever the pin says: an earlier
// revision aliased the two openers, so logout removed the file entry twice and
// silently left a usable session in the Keychain, which reappeared the moment
// the pin was removed. Pinning storage must not narrow what logout revokes.
func UseFileBackend() {
	pinFileBackend = true
}

// primaryOpener is the backend Save and Load use. Clear does not consult it.
func primaryOpener() func() (keyring.Keyring, error) {
	if pinFileBackend {
		return openFileKeyring
	}
	return openKeyring
}

// SetOpenKeyringForTest swaps the keyring opener; it returns a restore func.
// Not safe for concurrent tests; intended for isolated test scenarios.
func SetOpenKeyringForTest(fn func() (keyring.Keyring, error)) (restore func()) {
	prev := openKeyring
	openKeyring = fn
	return func() { openKeyring = prev }
}

// SetOpenFileKeyringForTest swaps the file-backed fallback opener.
// Use with SetOpenKeyringForTest to exercise the fallback path in isolation.
func SetOpenFileKeyringForTest(fn func() (keyring.Keyring, error)) (restore func()) {
	prev := openFileKeyring
	openFileKeyring = fn
	return func() { openFileKeyring = prev }
}

func defaultOpenKeyring() (keyring.Keyring, error) {
	home, _ := os.UserHomeDir()
	return keyring.Open(keyring.Config{
		ServiceName: serviceName,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
			keyring.WinCredBackend,
			keyring.FileBackend,
		},
		FileDir:          filepath.Join(home, ".config", "eightctl", "keyring"),
		FilePasswordFunc: filePassword,
	})
}

func defaultOpenFileKeyring() (keyring.Keyring, error) {
	home, _ := os.UserHomeDir()
	return keyring.Open(keyring.Config{
		ServiceName:      serviceName,
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          filepath.Join(home, ".config", "eightctl", "keyring"),
		FilePasswordFunc: filePassword,
	})
}

func filePassword(_ string) (string, error) {
	return serviceName + "-fallback", nil
}

func Save(id Identity, token string, expiresAt time.Time, userID string) error {
	data, err := json.Marshal(CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	item := keyring.Item{
		Key:   storageKey(id),
		Label: serviceName + " token",
		Data:  data,
	}

	primaryErr := trySetWith(primaryOpener(), item)
	if primaryErr == nil {
		log.Debug("keyring saved token")
		return nil
	}
	if pinFileBackend {
		// The file backend is the pinned target; there is nothing to fall back to.
		return primaryErr
	}
	log.Debug("primary keyring set failed; falling back to file backend", "error", primaryErr)

	if fileErr := trySetWith(openFileKeyring, item); fileErr != nil {
		log.Debug("file keyring set failed", "error", fileErr)
		return primaryErr
	}
	log.Debug("keyring saved token to file fallback")
	return nil
}

func trySetWith(opener func() (keyring.Keyring, error), item keyring.Item) error {
	ring, err := opener()
	if err != nil {
		return err
	}
	return ring.Set(item)
}

// Load returns the cached token for the given Identity, if present and unexpired.
// Tokens are namespaced by Identity (base URL + client ID + email) — not by
// UserID — because a single OAuth principal (email) can legitimately act on
// multiple household userIDs. The cached UserID is informational metadata for
// callers that want to recover "which userID was primary at auth time."
func Load(id Identity) (*CachedToken, error) {
	cached, err := loadFrom(primaryOpener(), id)
	if err == nil {
		return cached, nil
	}
	if err != keyring.ErrKeyNotFound {
		log.Debug("primary keyring load failed", "error", err)
	}
	fallback, fallbackErr := loadFrom(openFileKeyring, id)
	if fallbackErr == nil {
		return fallback, nil
	}
	if fallbackErr != keyring.ErrKeyNotFound {
		log.Debug("file keyring load failed", "error", fallbackErr)
	}
	return nil, err
}

func loadFrom(opener func() (keyring.Keyring, error), id Identity) (*CachedToken, error) {
	ring, err := opener()
	if err != nil {
		log.Debug("keyring open failed (load)", "error", err)
		return nil, err
	}
	key := storageKey(id)
	item, err := ring.Get(key)
	if err == keyring.ErrKeyNotFound {
		legacyKey := cacheKey(id)
		item, err = ring.Get(legacyKey)
		if err == nil {
			key = legacyKey
		} else if isIgnorableLegacyKeyError(err) {
			err = keyring.ErrKeyNotFound
		}
	}
	if err == keyring.ErrKeyNotFound && id.Email == "" {
		// No email specified: attempt to find a single matching token for this base/client.
		if alt, findErr := findSingleForClient(ring, id); findErr == nil {
			key = alt
			item, err = ring.Get(key)
		} else {
			log.Debug("keyring wildcard lookup failed", "error", findErr)
		}
	}
	if err != nil {
		return nil, err
	}
	var cached CachedToken
	if err := json.Unmarshal(item.Data, &cached); err != nil {
		return nil, err
	}
	if time.Now().After(cached.ExpiresAt) {
		_ = ring.Remove(key)
		return nil, keyring.ErrKeyNotFound
	}
	return &cached, nil
}

// Clear revokes the cached token from every backend it could be in, ignoring
// pinFileBackend. Logout must not leave a usable session behind in the OS
// keyring just because this run was configured to read from a file.
func Clear(id Identity) error {
	primaryErr := clearFrom(openKeyring, id)
	fallbackErr := clearFrom(openFileKeyring, id)
	if primaryErr != nil && fallbackErr != nil {
		return primaryErr
	}
	return nil
}

func clearFrom(opener func() (keyring.Keyring, error), id Identity) error {
	ring, err := opener()
	if err != nil {
		return err
	}
	for _, key := range []string{storageKey(id), cacheKey(id)} {
		if err := ring.Remove(key); err != nil {
			if err == keyring.ErrKeyNotFound || os.IsNotExist(err) || isIgnorableLegacyKeyError(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func cacheKey(id Identity) string {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.BaseURL)), "/")
	email := strings.ToLower(strings.TrimSpace(id.Email))
	return tokenKey + ":" + base + "|" + id.ClientID + "|" + email
}

func storageKey(id Identity) string {
	return storageKeyV2Prefix + base64.RawURLEncoding.EncodeToString([]byte(cacheKey(id)))
}

func identityKeyFromStorageKey(key string) (string, bool) {
	if strings.HasPrefix(key, storageKeyV2Prefix) {
		raw := strings.TrimPrefix(key, storageKeyV2Prefix)
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return "", false
		}
		return string(decoded), true
	}
	if strings.HasPrefix(key, tokenKey+":") {
		return key, true
	}
	return "", false
}

func isIgnorableLegacyKeyError(err error) bool {
	if err == nil {
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "filename, directory name, or volume label syntax is incorrect")
}

// findSingleForClient finds a single cached key for the given base/client when email is unknown.
// Returns ErrKeyNotFound if none or multiple exist.
func findSingleForClient(ring keyring.Keyring, id Identity) (string, error) {
	keys, err := ring.Keys()
	if err != nil {
		return "", err
	}
	prefix := tokenKey + ":" + strings.TrimSuffix(strings.ToLower(strings.TrimSpace(id.BaseURL)), "/") + "|" + id.ClientID + "|"
	matches := []string{}
	for _, k := range keys {
		identityKey, ok := identityKeyFromStorageKey(k)
		if ok && strings.HasPrefix(identityKey, prefix) {
			matches = append(matches, k)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", keyring.ErrKeyNotFound
}
