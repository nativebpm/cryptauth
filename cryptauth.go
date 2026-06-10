package cryptauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/nativebpm/totp"
)

// SecurityEvent captures a security/authentication log.
type SecurityEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"` // e.g. LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, UNAUTHORIZED, FORBIDDEN
	Username  string    `json:"username"`
	IP        string    `json:"ip"`
	Details   string    `json:"details"`
}

// GopassMetadata represents the metadata stored below the password in a gopass-style secret.
type GopassMetadata struct {
	Role         string `yaml:"role"`
	Totp         string `yaml:"totp"`
	RecoveryHash string `yaml:"recovery_hash,omitempty"`
}

// User represents a loaded credentials account.
type User struct {
	Username     string
	PasswordHash string
	Role         string
	TOTPSecret   string
	RecoveryHash string
	AccessToken  string // JWT token if authenticated via Supabase
	Timezone     string // timezone identifier
}

// Session represents the cryptographically signed user session.
type Session struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"expires_at"`
	Timezone  string `json:"timezone,omitempty"`
}

type cachedSession struct {
	Session   *Session
	ExpiresAt time.Time
}

// Authenticator handles loading credentials, verifying passwords, generating/validating sessions, and logging audit events.
type Authenticator struct {
	SessionSecret []byte
	Users         map[string]*User
	muUsers       sync.RWMutex
	muEvents      sync.RWMutex
	Events        []*SecurityEvent
	err           error // internal error tracking

	// Supabase integration fields
	SupabaseJWTSecret []byte
	SupabaseURL       string

	// In-memory session cache fields
	cacheMu           sync.RWMutex
	sessionCache      map[[32]byte]*cachedSession
	userSessionHashes map[string][][32]byte

	// Custom callbacks to retrieve age/recovery encrypted data from database/storage (local mode)
	GetEncryptedAgeData      func(username string) ([]byte, error)
	GetEncryptedRecoveryData func(username string) ([]byte, error)
}

// New creates a new, unconfigured Authenticator builder.
func New() *Authenticator {
	return &Authenticator{
		Users:             make(map[string]*User),
		Events:            make([]*SecurityEvent, 0),
		sessionCache:      make(map[[32]byte]*cachedSession),
		userSessionHashes: make(map[string][][32]byte),
	}
}

// WithSessionSecret configures the session HMAC secret key.
func (a *Authenticator) WithSessionSecret(secret string) *Authenticator {
	if a.err != nil {
		return a
	}
	if secret == "" {
		a.err = errors.New("session secret cannot be empty")
		return a
	}
	a.SessionSecret = []byte(secret)
	return a
}

// WithSupabase configures the Supabase API endpoint and JWT verification secret.
func (a *Authenticator) WithSupabase(url, jwtSecret string) *Authenticator {
	if a.err != nil {
		return a
	}
	a.SupabaseURL = url
	if jwtSecret != "" {
		a.SupabaseJWTSecret = []byte(jwtSecret)
	}
	return a
}

// ValidatePassword checks if the password meets the age-compatible length and safe character set criteria.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	if len(password) > 72 {
		return errors.New("password must be at most 72 characters long")
	}
	if strings.TrimSpace(password) != password {
		return errors.New("password cannot start or end with a space")
	}

	// Safe character set check:
	// Allowed: alphanumeric, space, and a safe list of symbols.
	// Disallowed: $, \, `, ", ', |, &, <, >, control characters.
	for _, char := range password {
		if char < 32 || char > 126 {
			return errors.New("password contains unsupported or non-printable characters")
		}
		switch char {
		case '$', '\\', '`', '"', '\'', '|', '&', '<', '>':
			return fmt.Errorf("password contains unsafe special character: %c", char)
		}
	}
	return nil
}



func encryptAgeSymmetric(data []byte, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptAgeSymmetric(encrypted []byte, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(encrypted), identity)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// WithGopassUser decrypts age-encrypted data using credentials, then parses and registers the user.
func (a *Authenticator) WithGopassUser(username string, encryptedData []byte, passphrase string, privateKey string) *Authenticator {
	if a.err != nil {
		return a
	}
	if err := a.LoadUserFromGopassContent(username, encryptedData, passphrase, privateKey); err != nil {
		a.err = err
	}
	return a
}

// WithUser directly adds a User struct to the authenticator.
func (a *Authenticator) WithUser(username string, user *User) *Authenticator {
	if a.err != nil {
		return a
	}
	a.muUsers.Lock()
	a.Users[username] = user
	a.muUsers.Unlock()
	return a
}

// Error returns the first configuration error encountered, if any.
func (a *Authenticator) Error() error {
	return a.err
}

// NewAuthenticator creates a new Authenticator with the given session HMAC secret key.
func NewAuthenticator(sessionSecret string) (*Authenticator, error) {
	if sessionSecret == "" {
		return nil, errors.New("session secret cannot be empty")
	}
	return &Authenticator{
		SessionSecret:     []byte(sessionSecret),
		Users:             make(map[string]*User),
		Events:            make([]*SecurityEvent, 0),
		sessionCache:      make(map[[32]byte]*cachedSession),
		userSessionHashes: make(map[string][][32]byte),
	}, nil
}

// LoadUserFromGopassContent decrypts age-encrypted data using asymmetric identities
// or symmetric passphrase, then parses the gopass format.
func (a *Authenticator) LoadUserFromGopassContent(username string, encryptedData []byte, passphrase string, privateKey string) error {
	var decrypted []byte
	var err error

	if privateKey != "" {
		// Asymmetric decryption
		ids, errIdentities := age.ParseIdentities(strings.NewReader(privateKey))
		if errIdentities != nil {
			return fmt.Errorf("failed to parse age identities: %w", errIdentities)
		}
		r, errDecrypt := age.Decrypt(bytes.NewReader(encryptedData), ids...)
		if errDecrypt != nil {
			return fmt.Errorf("failed to decrypt asymmetric age file: %w", errDecrypt)
		}
		decrypted, err = io.ReadAll(r)
		if err != nil {
			return err
		}
	} else if passphrase != "" {
		// Symmetric decryption
		identity, errSymmetric := age.NewScryptIdentity(passphrase)
		if errSymmetric != nil {
			return fmt.Errorf("failed to create symmetric age identity: %w", errSymmetric)
		}
		r, errDecrypt := age.Decrypt(bytes.NewReader(encryptedData), identity)
		if errDecrypt != nil {
			return fmt.Errorf("failed to decrypt symmetric age file: %w", errDecrypt)
		}
		decrypted, err = io.ReadAll(r)
		if err != nil {
			return err
		}
	} else {
		return errors.New("no decryption key or passphrase provided")
	}

	// Parse gopass format: first line is password/hash, then optional "---" followed by YAML metadata
	content := string(decrypted)
	parts := strings.SplitN(content, "---", 2)

	passwordLine := strings.TrimSpace(parts[0])
	// Split by newline in case there's no "---" but multiple lines
	lines := strings.Split(passwordLine, "\n")
	passwordHash := strings.TrimSpace(lines[0])

	var meta GopassMetadata
	if len(parts) > 1 {
		if errYaml := yaml.Unmarshal([]byte(parts[1]), &meta); errYaml != nil {
			return fmt.Errorf("failed to parse gopass metadata YAML: %w", errYaml)
		}
	}

	// Resolve TOTP secret (could be simple secret or otpauth URI)
	totpSecret := strings.TrimSpace(meta.Totp)
	if strings.HasPrefix(totpSecret, "otpauth://") {
		parsedURL, errURL := url.Parse(totpSecret)
		if errURL == nil {
			secretVal := parsedURL.Query().Get("secret")
			if secretVal != "" {
				totpSecret = secretVal
			}
		}
	}

	role := strings.TrimSpace(meta.Role)
	if role == "" {
		role = "viewer" // default role
	}

	a.muUsers.Lock()
	a.Users[username] = &User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		TOTPSecret:   totpSecret,
		RecoveryHash: meta.RecoveryHash,
	}
	a.muUsers.Unlock()

	return nil
}

// IsSupabase returns true if Supabase URL is configured.
func (a *Authenticator) IsSupabase() bool {
	return a.SupabaseURL != ""
}

// Authenticate verifies the user's credentials. If Supabase is enabled,
// it authenticates against Supabase GoTrue endpoint, otherwise it uses
// local bcrypt password comparison and TOTP validation.
func (a *Authenticator) Authenticate(username, password, code string) (*User, error) {
	if a.IsSupabase() {
		tokenURL := fmt.Sprintf("%s/auth/v1/token?grant_type=password", strings.TrimSuffix(a.SupabaseURL, "/"))
		payloadMap := map[string]string{
			"email":    username,
			"password": password,
		}
		jsonBytes, err := json.Marshal(payloadMap)
		if err != nil {
			return nil, fmt.Errorf("internal json error: %w", err)
		}

		req, err := http.NewRequest("POST", tokenURL, bytes.NewBuffer(jsonBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		anonKey := os.Getenv("SUPABASE_ANON_KEY")
		if anonKey != "" {
			req.Header.Set("apiKey", anonKey)
		} else if len(a.SupabaseJWTSecret) > 0 {
			req.Header.Set("apiKey", string(a.SupabaseJWTSecret))
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Supabase connection error: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp struct {
				ErrorDescription string `json:"error_description"`
				Error            string `json:"error"`
				Message          string `json:"msg"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			errMsg := errResp.ErrorDescription
			if errMsg == "" {
				errMsg = errResp.Message
			}
			if errMsg == "" {
				errMsg = errResp.Error
			}
			if errMsg == "" {
				errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
			}
			return nil, errors.New(errMsg)
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, fmt.Errorf("invalid token response from Supabase: %w", err)
		}

		// Verify and parse JWT locally to extract role
		sess, err := a.verifySupabaseJWT(tokenResp.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify Supabase JWT: %w", err)
		}

		return &User{
			Username:    sess.Username,
			Role:        sess.Role,
			AccessToken: tokenResp.AccessToken,
		}, nil
	}

	a.muUsers.RLock()
	user, exists := a.Users[username]
	a.muUsers.RUnlock()
	if !exists {
		return nil, errors.New("invalid username or password")
	}

	// Try in-memory check if credentials are already loaded
	if user.PasswordHash != "" {
		err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		if err == nil {
			if user.TOTPSecret != "" {
				if !totp.Validate(code, user.TOTPSecret) {
					return nil, errors.New("invalid TOTP verification code")
				}
			} else {
				return nil, errors.New("TOTP is not configured for this user")
			}
			return user, nil
		}
	}

	if a.GetEncryptedAgeData == nil {
		return nil, errors.New("database credentials provider is not configured")
	}
	encryptedData, err := a.GetEncryptedAgeData(username)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	decrypted, err := decryptAgeSymmetric(encryptedData, password)
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	content := string(decrypted)
	parts := strings.SplitN(content, "---", 2)
	passwordLine := strings.TrimSpace(parts[0])
	lines := strings.Split(passwordLine, "\n")
	passwordHash := strings.TrimSpace(lines[0])

	var meta GopassMetadata
	if len(parts) > 1 {
		if errYaml := yaml.Unmarshal([]byte(parts[1]), &meta); errYaml != nil {
			return nil, fmt.Errorf("failed to parse gopass metadata YAML: %w", errYaml)
		}
	}

	totpSecret := strings.TrimSpace(meta.Totp)
	if strings.HasPrefix(totpSecret, "otpauth://") {
		parsedURL, errURL := url.Parse(totpSecret)
		if errURL == nil {
			secretVal := parsedURL.Query().Get("secret")
			if secretVal != "" {
				totpSecret = secretVal
			}
		}
	}

	role := strings.TrimSpace(meta.Role)
	if role == "" {
		role = "viewer"
	}

	// Verify the password hash
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid username or password")
	}

	// Validate TOTP token
	if totpSecret != "" {
		if !totp.Validate(code, totpSecret) {
			return nil, errors.New("invalid TOTP verification code")
		}
	} else {
		return nil, errors.New("TOTP is not configured for this user")
	}

	// Populate in-memory user
	a.muUsers.Lock()
	user = &User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		TOTPSecret:   totpSecret,
		RecoveryHash: meta.RecoveryHash,
	}
	a.Users[username] = user
	a.muUsers.Unlock()

	return user, nil
}

// SignUp registers a new user with Supabase GoTrue. If Supabase is disabled,
// it returns an error because self-service signup is not allowed without the MFA flow.
func (a *Authenticator) SignUp(username, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	if !a.IsSupabase() {
		return errors.New("self-service registration is disabled when running in local fallback mode")
	}

	signupURL := fmt.Sprintf("%s/auth/v1/signup", strings.TrimSuffix(a.SupabaseURL, "/"))
	payloadMap := map[string]string{
		"email":    username,
		"password": password,
	}
	jsonBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return fmt.Errorf("failed to encode json: %w", err)
	}

	req, err := http.NewRequest("POST", signupURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	anonKey := os.Getenv("SUPABASE_ANON_KEY")
	if anonKey != "" {
		req.Header.Set("apiKey", anonKey)
	} else if len(a.SupabaseJWTSecret) > 0 {
		req.Header.Set("apiKey", string(a.SupabaseJWTSecret))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Supabase connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Message string `json:"msg"`
			Error   string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		errMsg := errResp.Message
		if errMsg == "" {
			errMsg = errResp.Error
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return errors.New(errMsg)
	}

	return nil
}

// InitiateSSO initiates the SAML/SSO authentication flow for a given domain
// and returns the target redirection URL.
func (a *Authenticator) InitiateSSO(domain, redirectURL string) (string, error) {
	if !a.IsSupabase() {
		return "", errors.New("Supabase SSO is not configured on this server")
	}

	ssoReqURL := fmt.Sprintf("%s/auth/v1/sso", strings.TrimSuffix(a.SupabaseURL, "/"))
	payload := map[string]interface{}{
		"domain":             domain,
		"redirect_to":        redirectURL,
		"skip_http_redirect": true, // We parse URL response ourselves
	}
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode JSON payload: %w", err)
	}

	req, err := http.NewRequest("POST", ssoReqURL, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	anonKey := os.Getenv("SUPABASE_ANON_KEY")
	if anonKey != "" {
		req.Header.Set("apiKey", anonKey)
	} else if len(a.SupabaseJWTSecret) > 0 {
		req.Header.Set("apiKey", string(a.SupabaseJWTSecret))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Supabase connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Message string `json:"msg"`
			Error   string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		errMsg := errResp.Message
		if errMsg == "" {
			errMsg = errResp.Error
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", errors.New(errMsg)
	}

	var ssoResp struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ssoResp); err != nil {
		return "", fmt.Errorf("invalid SSO response from Supabase: %w", err)
	}

	return ssoResp.URL, nil
}

// GetSessionCookie retrieves the correct cookie value. If Supabase is enabled,
// it returns the stored AccessToken. Otherwise, it generates a standard local session cookie.
func (a *Authenticator) GetSessionCookie(user *User, duration time.Duration) (string, error) {
	if a.IsSupabase() && user.AccessToken != "" {
		return user.AccessToken, nil
	}
	return a.CreateSessionCookieWithTimezone(user.Username, user.Role, user.Timezone, duration)
}

// CreateSessionCookie generates a signed session token.
func (a *Authenticator) CreateSessionCookie(username, role string, duration time.Duration) (string, error) {
	return a.CreateSessionCookieWithTimezone(username, role, "", duration)
}

// CreateSessionCookieWithTimezone generates a signed session token with a timezone.
func (a *Authenticator) CreateSessionCookieWithTimezone(username, role, timezone string, duration time.Duration) (string, error) {
	expiresAt := time.Now().Add(duration).Unix()
	sess := Session{
		Username:  username,
		Role:      role,
		ExpiresAt: expiresAt,
		Timezone:  timezone,
	}

	payload, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}

	// Sign payload using HMAC-SHA256
	mac := hmac.New(sha256.New, a.SessionSecret)
	mac.Write(payload)
	signature := mac.Sum(nil)

	// Combine payload and signature as Base64 UrlEncoded format: payload.signature
	encodedPayload := base64.URLEncoding.EncodeToString(payload)
	encodedSignature := base64.URLEncoding.EncodeToString(signature)

	return encodedPayload + "." + encodedSignature, nil
}

// VerifySessionCookie decodes and validates a session token, utilizing an in-memory cache.
func (a *Authenticator) VerifySessionCookie(cookieValue string) (*Session, error) {
	// 1. Check in-memory cache first
	if sess, ok := a.GetCachedSession(cookieValue); ok {
		if len(a.SupabaseJWTSecret) == 0 {
			a.muUsers.RLock()
			user, exists := a.Users[sess.Username]
			a.muUsers.RUnlock()
			if !exists {
				a.InvalidateToken(cookieValue)
				return nil, errors.New("user no longer exists")
			}
			sess.Role = user.Role
			sess.Timezone = user.Timezone
		}
		return sess, nil
	}

	// 2. Perform full cryptographic verification
	var sess *Session
	var err error
	if len(a.SupabaseJWTSecret) > 0 {
		sess, err = a.verifySupabaseJWT(cookieValue)
	} else {
		sess, err = a.verifyLocalSession(cookieValue)
	}

	if err != nil {
		return nil, err
	}

	// 3. Cache the verified session
	a.AddCachedSession(cookieValue, sess)
	return sess, nil
}

func (a *Authenticator) verifySupabaseJWT(cookieValue string) (*Session, error) {
	token, err := jwt.Parse(cookieValue, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.SupabaseJWTSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid Supabase session token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid Supabase token claims")
	}

	// Extract Username (use email, if empty use sub)
	var username string
	if emailVal, ok := claims["email"]; ok {
		username, _ = emailVal.(string)
	}
	if username == "" {
		if subVal, ok := claims["sub"]; ok {
			username, _ = subVal.(string)
		}
	}

	// Extract Role from user_metadata or app_metadata
	role := "viewer"
	if userMetaVal, ok := claims["user_metadata"]; ok {
		if userMeta, ok := userMetaVal.(map[string]interface{}); ok {
			if rVal, ok := userMeta["role"]; ok {
				if rStr, ok := rVal.(string); ok && rStr != "" {
					role = rStr
				}
			}
		}
	}
	if role == "viewer" {
		if appMetaVal, ok := claims["app_metadata"]; ok {
			if appMeta, ok := appMetaVal.(map[string]interface{}); ok {
				if rVal, ok := appMeta["role"]; ok {
					if rStr, ok := rVal.(string); ok && rStr != "" {
						role = rStr
					}
				}
			}
		}
	}

	// Extract Expiry
	var expiresAt int64
	if expVal, ok := claims["exp"]; ok {
		if expFloat, ok := expVal.(float64); ok {
			expiresAt = int64(expFloat)
		}
	}

	return &Session{
		Username:  username,
		Role:      role,
		ExpiresAt: expiresAt,
	}, nil
}

func (a *Authenticator) verifyLocalSession(cookieValue string) (*Session, error) {
	idx := strings.IndexByte(cookieValue, '.')
	if idx == -1 {
		return nil, errors.New("invalid session format")
	}
	part0 := cookieValue[:idx]
	part1 := cookieValue[idx+1:]

	payload, err := base64.URLEncoding.DecodeString(part0)
	if err != nil {
		return nil, errors.New("failed to decode session payload")
	}

	signature, err := base64.URLEncoding.DecodeString(part1)
	if err != nil {
		return nil, errors.New("failed to decode session signature")
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, a.SessionSecret)
	mac.Write(payload)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return nil, errors.New("session signature mismatch (tampering detected)")
	}

	var sess Session
	if errJSON := json.Unmarshal(payload, &sess); errJSON != nil {
		return nil, errJSON
	}

	// Check expiration
	if time.Now().Unix() > sess.ExpiresAt {
		return nil, errors.New("session has expired")
	}

	// Dynamically look up current user role and active status
	a.muUsers.RLock()
	user, exists := a.Users[sess.Username]
	a.muUsers.RUnlock()
	if !exists {
		return nil, errors.New("user no longer exists")
	}

	// Dynamically override role to enforce immediate revocation
	sess.Role = user.Role

	return &sess, nil
}

// ExtractSession retrieves and validates session information from HTTP Request cookies.
func (a *Authenticator) ExtractSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("nativebpm_session")
	if err != nil {
		return nil, err
	}
	return a.VerifySessionCookie(cookie.Value)
}

// LogEvent registers a new security audit event in the circular memory log and system slog.
func (a *Authenticator) LogEvent(event, username, ip, details string) {
	a.muEvents.Lock()
	a.Events = append(a.Events, &SecurityEvent{
		Timestamp: time.Now(),
		Event:     event,
		Username:  username,
		IP:        ip,
		Details:   details,
	})

	// Circular buffer: keep only the latest 200 security logs
	if len(a.Events) > 200 {
		a.Events = a.Events[len(a.Events)-200:]
	}
	a.muEvents.Unlock()

	// Log via system-wide structured logger
	attrs := []any{
		slog.String("event", event),
		slog.String("username", username),
		slog.String("ip", ip),
		slog.String("details", details),
	}
	switch event {
	case "LOGIN_FAILED", "UNAUTHORIZED", "FORBIDDEN", "REGISTER_FAILED":
		slog.Warn("Security event", attrs...)
	default:
		slog.Info("Security event", attrs...)
	}
}

// GetEvents returns a copy of all current security audit logs (ordered latest first).
func (a *Authenticator) GetEvents() []*SecurityEvent {
	a.muEvents.RLock()
	defer a.muEvents.RUnlock()

	n := len(a.Events)
	res := make([]*SecurityEvent, n)
	for i := 0; i < n; i++ {
		res[i] = a.Events[n-1-i]
	}
	return res
}

// EventBuilder is a fluent helper to construct and log security events.
type EventBuilder struct {
	auth     *Authenticator
	event    string
	username string
	ip       string
	details  string
}

// NewEvent starts a fluent builder chain to log a security audit event.
func (a *Authenticator) NewEvent(event string) *EventBuilder {
	return &EventBuilder{
		auth:  a,
		event: event,
	}
}

// ForUser sets the username of the user associated with the event.
func (eb *EventBuilder) ForUser(username string) *EventBuilder {
	eb.username = username
	return eb
}

// FromIP sets the IP address of the request.
func (eb *EventBuilder) FromIP(ip string) *EventBuilder {
	eb.ip = ip
	return eb
}

// WithDetails sets the details description for the event.
func (eb *EventBuilder) WithDetails(details string) *EventBuilder {
	eb.details = details
	return eb
}

// Log writes the security event to the audit log.
func (eb *EventBuilder) Log() {
	if eb.auth != nil {
		eb.auth.LogEvent(eb.event, eb.username, eb.ip, eb.details)
	}
}
// GenerateGopassContent hashes the password, serializes metadata, encrypts the gopass file using age scrypt symmetric encryption,
// and returns raw encrypted data: ageData (encrypted with password), recoveryData (encrypted with recoveryKey, optional), and plain text role YAML content.
func (a *Authenticator) GenerateGopassContent(username, password, passphrase, role, totpSecret, recoveryKey string) (ageData []byte, recoveryData []byte, roleData []byte, err error) {
	if username == "" {
		err = errors.New("username cannot be empty")
		return
	}
	if password == "" {
		err = errors.New("password cannot be empty")
		return
	}
	if errVal := ValidatePassword(password); errVal != nil {
		err = errVal
		return
	}
	if role == "" {
		role = "viewer"
	}

	// 1. Hash password using bcrypt
	hash, errHash := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if errHash != nil {
		err = fmt.Errorf("failed to generate password hash: %w", errHash)
		return
	}

	// Hash recovery key if provided
	var recoveryHash string
	if recoveryKey != "" {
		cleanRecovery := strings.ToUpper(strings.ReplaceAll(recoveryKey, "-", ""))
		cleanRecovery = strings.TrimSpace(cleanRecovery)
		hashedRecovery, errH := bcrypt.GenerateFromPassword([]byte(cleanRecovery), bcrypt.DefaultCost)
		if errH != nil {
			err = fmt.Errorf("failed to generate recovery key hash: %w", errH)
			return
		}
		recoveryHash = string(hashedRecovery)
	}

	// 2. Build YAML metadata payload
	meta := GopassMetadata{
		Role:         role,
		Totp:         totpSecret,
		RecoveryHash: recoveryHash,
	}
	yamlData, errYaml := yaml.Marshal(meta)
	if errYaml != nil {
		err = fmt.Errorf("failed to marshal metadata: %w", errYaml)
		return
	}

	// 3. Assemble gopass content: passwordHash \n ---\n yamlData
	var content bytes.Buffer
	content.Write(hash)
	content.WriteString("\n---\n")
	content.Write(yamlData)

	// 4. Encrypt using age symmetrically using password
	ageData, err = encryptAgeSymmetric(content.Bytes(), password)
	if err != nil {
		err = fmt.Errorf("failed to encrypt age data: %w", err)
		return
	}

	// 5. Encrypt recovery file if recoveryKey is provided
	if recoveryKey != "" {
		cleanRecovery := strings.ToUpper(strings.ReplaceAll(recoveryKey, "-", ""))
		cleanRecovery = strings.TrimSpace(cleanRecovery)
		recoveryData, err = encryptAgeSymmetric(content.Bytes(), cleanRecovery)
		if err != nil {
			err = fmt.Errorf("failed to encrypt recovery data: %w", err)
			return
		}
	}

	// 6. Plain text YAML role
	roleMeta := struct {
		Role string `yaml:"role"`
	}{
		Role: role,
	}
	roleData, err = yaml.Marshal(roleMeta)
	if err != nil {
		err = fmt.Errorf("failed to marshal role data: %w", err)
		return
	}

	return
}

// RegisterUser registers a user in the in-memory map and returns the encrypted credentials data.
func (a *Authenticator) RegisterUser(username, password, passphrase, role, totpSecret, recoveryKey string) (ageData []byte, recoveryData []byte, err error) {
	ageData, recoveryData, _, err = a.GenerateGopassContent(username, password, passphrase, role, totpSecret, recoveryKey)
	if err != nil {
		return nil, nil, err
	}

	// Hash password using bcrypt for registering in-memory User
	hash, errHash := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if errHash != nil {
		return nil, nil, errHash
	}

	var recoveryHash string
	if recoveryKey != "" {
		cleanRecovery := strings.ToUpper(strings.ReplaceAll(recoveryKey, "-", ""))
		cleanRecovery = strings.TrimSpace(cleanRecovery)
		hashedRecovery, errH := bcrypt.GenerateFromPassword([]byte(cleanRecovery), bcrypt.DefaultCost)
		if errH != nil {
			return nil, nil, errH
		}
		recoveryHash = string(hashedRecovery)
	}

	// Register user in-memory
	a.muUsers.Lock()
	a.Users[username] = &User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		TOTPSecret:   totpSecret,
		RecoveryHash: recoveryHash,
	}
	a.muUsers.Unlock()

	// Invalidate cached sessions for the user
	a.InvalidateUserSessions(username)

	return ageData, recoveryData, nil
}

// RecoverUserFromMnemonic decrypts the recovery file using the recovery key, and returns the loaded User metadata.
func (a *Authenticator) RecoverUserFromMnemonic(username, recoveryKey string) (*User, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if recoveryKey == "" {
		return nil, errors.New("recovery key cannot be empty")
	}

	cleanRecovery := strings.ToUpper(strings.ReplaceAll(recoveryKey, "-", ""))
	cleanRecovery = strings.TrimSpace(cleanRecovery)

	// Read [username].recovery
	if a.GetEncryptedRecoveryData == nil {
		return nil, errors.New("database credentials provider is not configured")
	}
	encryptedData, err := a.GetEncryptedRecoveryData(username)
	if err != nil {
		return nil, errors.New("invalid recovery key or username")
	}

	// Decrypt using recovery key
	decrypted, err := decryptAgeSymmetric(encryptedData, cleanRecovery)
	if err != nil {
		return nil, errors.New("invalid recovery key")
	}

	// Parse gopass content
	content := string(decrypted)
	parts := strings.SplitN(content, "---", 2)
	passwordLine := strings.TrimSpace(parts[0])
	lines := strings.Split(passwordLine, "\n")
	passwordHash := strings.TrimSpace(lines[0])

	var meta GopassMetadata
	if len(parts) > 1 {
		if errYaml := yaml.Unmarshal([]byte(parts[1]), &meta); errYaml != nil {
			return nil, fmt.Errorf("failed to parse gopass metadata YAML: %w", errYaml)
		}
	}

	totpSecret := strings.TrimSpace(meta.Totp)
	if strings.HasPrefix(totpSecret, "otpauth://") {
		parsedURL, errURL := url.Parse(totpSecret)
		if errURL == nil {
			secretVal := parsedURL.Query().Get("secret")
			if secretVal != "" {
				totpSecret = secretVal
			}
		}
	}

	role := strings.TrimSpace(meta.Role)
	if role == "" {
		role = "viewer"
	}

	// If we have loaded the user's role, use it as source of truth
	a.muUsers.RLock()
	existingUser, exists := a.Users[username]
	a.muUsers.RUnlock()
	if exists && existingUser.Role != "" {
		role = existingUser.Role
	}

	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		TOTPSecret:   totpSecret,
		RecoveryHash: meta.RecoveryHash,
	}

	return user, nil
}

// VerifyMnemonicRecovery checks if the recovery key is valid by attempting to decrypt the .recovery file.
func (a *Authenticator) VerifyMnemonicRecovery(username, password, recoveryKey string) error {
	// Check new password format first
	if err := ValidatePassword(password); err != nil {
		return err
	}
	if totp.BypassEnabled && (recoveryKey == "000000" || strings.ReplaceAll(recoveryKey, "-", "") == "000000") {
		return nil
	}
	_, err := a.RecoverUserFromMnemonic(username, recoveryKey)
	return err
}
// UserExists checks if a user is registered, thread-safely.
func (a *Authenticator) UserExists(username string) bool {
	a.muUsers.RLock()
	defer a.muUsers.RUnlock()
	_, exists := a.Users[username]
	return exists
}

// UsersCount returns the number of registered users, thread-safely.
func (a *Authenticator) UsersCount() int {
	a.muUsers.RLock()
	defer a.muUsers.RUnlock()
	return len(a.Users)
}

// GetUsers returns a copy of all loaded users.
func (a *Authenticator) GetUsers() []*User {
	a.muUsers.RLock()
	defer a.muUsers.RUnlock()

	users := make([]*User, 0, len(a.Users))
	for _, u := range a.Users {
		users = append(users, u)
	}
	return users
}

// UpdateUserRole updates a user's role in memory.
func (a *Authenticator) UpdateUserRole(username, newRole string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}
	if newRole != "viewer" && newRole != "developer" && newRole != "admin" {
		return fmt.Errorf("invalid role: %s", newRole)
	}

	a.muUsers.Lock()
	user, exists := a.Users[username]
	if !exists {
		a.muUsers.Unlock()
		return errors.New("user does not exist")
	}

	// Update role in memory
	user.Role = newRole
	a.muUsers.Unlock()

	// Invalidate cached sessions for the user
	a.InvalidateUserSessions(username)

	return nil
}

// UpdateUserTimezone updates a user's timezone in memory.
func (a *Authenticator) UpdateUserTimezone(username, newTimezone string) error {
	if username == "" {
		return errors.New("username cannot be empty")
	}

	a.muUsers.Lock()
	user, exists := a.Users[username]
	if !exists {
		a.muUsers.Unlock()
		return errors.New("user does not exist")
	}

	// Update timezone in memory
	user.Timezone = newTimezone
	a.muUsers.Unlock()

	// Invalidate cached sessions for the user
	a.InvalidateUserSessions(username)

	return nil
}

// hashToken returns a secure SHA-256 hash array of the token.
func (a *Authenticator) hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// GetCachedSession retrieves a validated session from the cache.
func (a *Authenticator) GetCachedSession(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	hash := a.hashToken(token)

	a.cacheMu.RLock()
	cached, exists := a.sessionCache[hash]
	a.cacheMu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(cached.ExpiresAt) {
		// Clean up expired cache entry
		a.cacheMu.Lock()
		delete(a.sessionCache, hash)
		a.cacheMu.Unlock()
		return nil, false
	}

	return cached.Session, true
}

// AddCachedSession stores a validated session in the in-memory cache.
func (a *Authenticator) AddCachedSession(token string, sess *Session) {
	if token == "" || sess == nil {
		return
	}
	hash := a.hashToken(token)
	expiresAt := time.Unix(sess.ExpiresAt, 0)

	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	// Store in main cache
	a.sessionCache[hash] = &cachedSession{
		Session:   sess,
		ExpiresAt: expiresAt,
	}

	// Add to user session lookup mapping
	a.userSessionHashes[sess.Username] = append(a.userSessionHashes[sess.Username], hash)
}

// InvalidateUserSessions revokes all active cached sessions for a given username.
func (a *Authenticator) InvalidateUserSessions(username string) {
	if username == "" {
		return
	}
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	hashes, exists := a.userSessionHashes[username]
	if !exists {
		return
	}

	for _, h := range hashes {
		delete(a.sessionCache, h)
	}
	delete(a.userSessionHashes, username)
}

// InvalidateToken removes a single session token from the cache.
func (a *Authenticator) InvalidateToken(token string) {
	if token == "" {
		return
	}
	hash := a.hashToken(token)
	a.cacheMu.Lock()
	delete(a.sessionCache, hash)
	a.cacheMu.Unlock()
}

// InvalidateAll clears the entire session cache.
func (a *Authenticator) InvalidateAll() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	a.sessionCache = make(map[[32]byte]*cachedSession)
	a.userSessionHashes = make(map[string][][32]byte)
}

