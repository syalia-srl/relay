package pushgw

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultEndpoint is FCM's API; PUSHGW_FCM_ENDPOINT overrides it for tests.
	DefaultEndpoint = "https://fcm.googleapis.com"
	fcmScope        = "https://www.googleapis.com/auth/firebase.messaging"
	jwtBearerGrant  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	tokenEarly      = time.Minute // an access token is renewed this long before it expires
)

// serviceAccount is the part of the FCM service-account JSON the gateway uses.
type serviceAccount struct {
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// FCM sends FCM HTTP v1 messages with an access token minted from a service
// account (RS256 JWT bearer grant) and cached until near its expiry.
type FCM struct {
	sendURL string
	account serviceAccount
	key     *rsa.PrivateKey
	client  *http.Client

	mu      sync.Mutex
	access  string
	expires time.Time
}

// NewFCM reads the service-account file. Its errors never quote the file.
func NewFCM(credentialsPath, endpoint string) (*FCM, error) {
	data, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, errors.New("FCM credentials not readable")
	}
	var account serviceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, errors.New("FCM credentials are not valid JSON")
	}
	if account.ProjectID == "" || account.ClientEmail == "" || account.TokenURI == "" {
		return nil, errors.New("FCM credentials lack project_id, client_email or token_uri")
	}
	key, err := parseRSAKey(account.PrivateKey)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &FCM{
		sendURL: strings.TrimRight(endpoint, "/") + "/v1/projects/" + url.PathEscape(account.ProjectID) + "/messages:send",
		account: account,
		key:     key,
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func parseRSAKey(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("FCM credentials hold no PEM private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("FCM credentials hold a key that is not RSA")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("FCM credentials hold an unreadable private key")
	}
	return key, nil
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// assertion is the signed JWT of the bearer grant.
func (f *FCM) assertion(now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   f.account.ClientEmail,
		"scope": fcmScope,
		"aud":   f.account.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signing := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// accessToken returns the cached token, minting a new one near expiry.
func (f *FCM) accessToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.access != "" && now.Before(f.expires) {
		return f.access, nil
	}
	jwt, err := f.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {jwtBearerGrant}, "assertion": {jwt}}
	resp, err := f.client.PostForm(f.account.TokenURI, form)
	if err != nil {
		return "", errors.New("token endpoint not reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint answered %d", resp.StatusCode)
	}
	var answer struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil || answer.AccessToken == "" {
		return "", errors.New("token endpoint answer has no access_token")
	}
	f.access = answer.AccessToken
	f.expires = now.Add(time.Duration(answer.ExpiresIn)*time.Second - tokenEarly)
	return f.access, nil
}

// forget drops the cached token, after FCM refused it.
func (f *FCM) forget(token string) {
	f.mu.Lock()
	if f.access == token {
		f.access = ""
	}
	f.mu.Unlock()
}

// Outcome is what FCM made of one token.
type Outcome int

const (
	Sent      Outcome = iota
	Invalid           // UNREGISTERED or INVALID_ARGUMENT: the relay should forget the token
	Transient         // FCM 429 or 5xx, or no access token: try the batch later
	Failed            // anything else; the token is kept
)

// Send sends token one data-only message. retryAfter is FCM's, for Transient.
func (f *FCM) Send(token string) (Outcome, time.Duration) {
	access, err := f.accessToken()
	if err != nil {
		return Transient, 0
	}
	body, _ := json.Marshal(map[string]any{"message": map[string]any{
		"token":   token,
		"data":    map[string]string{"w": "1"},
		"android": map[string]string{"priority": "high"},
	}})
	req, err := http.NewRequest(http.MethodPost, f.sendURL, bytes.NewReader(body))
	if err != nil {
		return Failed, 0
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return Transient, 0
	}
	defer resp.Body.Close()
	var retryAfter time.Duration
	if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
		retryAfter = time.Duration(secs) * time.Second
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return Sent, 0
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return Transient, retryAfter
	case resp.StatusCode == http.StatusUnauthorized:
		f.forget(access)
		return Transient, 0
	}
	if code := errorCode(io.LimitReader(resp.Body, 1<<20)); code == "UNREGISTERED" || code == "INVALID_ARGUMENT" {
		return Invalid, 0
	}
	return Failed, 0
}

// errorCode reads FCM's error: the FcmError detail's errorCode, else the status.
func errorCode(body io.Reader) string {
	var answer struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.NewDecoder(body).Decode(&answer) != nil {
		return ""
	}
	for _, d := range answer.Error.Details {
		if strings.HasSuffix(d.Type, "google.firebase.fcm.v1.FcmError") && d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return answer.Error.Status
}
