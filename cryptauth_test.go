package cryptauth

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/nativebpm/totp"
)

func TestAuthWithSymmetricGopassSecret(t *testing.T) {
	// 1. Prepare secret content in gopass style
	password := "my-secret-pass"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	secretContent := string(hash) + "\n---\nrole: admin\ntotp: JBSWY3DPEHPK3PXP\n"

	// 2. Encrypt it with age symmetrically
	passphrase := "master-key-123"
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatalf("Failed to create scrypt recipient: %v", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("Failed to create age encryptor: %v", err)
	}

	_, err = io.WriteString(w, secretContent)
	if err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}
	w.Close()

	// 3. Initialize Authenticator
	auth, err := NewAuthenticator("my-signing-secret")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// 4. Load from encrypted data
	err = auth.LoadUserFromGopassContent("admin", buf.Bytes(), passphrase, "")
	if err != nil {
		t.Fatalf("LoadUserFromGopassContent failed: %v", err)
	}

	// Check loaded user properties
	user, ok := auth.Users["admin"]
	if !ok {
		t.Fatal("User admin was not loaded")
	}
	if user.Role != "admin" {
		t.Errorf("Expected role admin, got %q", user.Role)
	}
	if user.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Expected TOTPSecret JBSWY3DPEHPK3PXP, got %q", user.TOTPSecret)
	}

	// 5. Test Authentication
	// Generate valid TOTP token for current time
	totpToken, err := totp.Generate("JBSWY3DPEHPK3PXP", time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to generate TOTP token: %v", err)
	}

	// Correct auth
	u, err := auth.Authenticate("admin", password, totpToken)
	if err != nil {
		t.Errorf("Authentication failed with valid credentials: %v", err)
	}
	if u.Username != "admin" {
		t.Errorf("Expected username admin, got %s", u.Username)
	}

	// Wrong password
	_, err = auth.Authenticate("admin", "wrong-pass", totpToken)
	if err == nil {
		t.Error("Authentication succeeded with wrong password")
	}

	// Wrong TOTP
	_, err = auth.Authenticate("admin", password, "000000")
	if err == nil {
		t.Error("Authentication succeeded with wrong TOTP token")
	}
}

func TestAuthWithAsymmetricGopassSecretAndOtpauthURI(t *testing.T) {
	// 1. Prepare secret content with otpauth:// URL
	password := "user-pass"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}

	secretContent := string(hash) + "\n---\nrole: developer\ntotp: otpauth://totp/NativeBPM:dev?secret=KVKVE43VNVSTSMKM&issuer=NativeBPM\n"

	// 2. Generate age keypair and encrypt
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("Failed to generate X25519 identity: %v", err)
	}
	recipient := identity.Recipient()

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		t.Fatalf("Failed to create age encryptor: %v", err)
	}
	_, err = io.WriteString(w, secretContent)
	if err != nil {
		t.Fatalf("Failed to write secret: %v", err)
	}
	w.Close()

	// 3. Initialize Authenticator
	auth, err := NewAuthenticator("my-signing-secret")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// 4. Load from encrypted data
	err = auth.LoadUserFromGopassContent("dev", buf.Bytes(), "", identity.String())
	if err != nil {
		t.Fatalf("LoadUserFromGopassContent failed: %v", err)
	}

	// Check loaded user properties
	user, ok := auth.Users["dev"]
	if !ok {
		t.Fatal("User dev was not loaded")
	}
	if user.Role != "developer" {
		t.Errorf("Expected role developer, got %q", user.Role)
	}
	// Verify otpauth secret was parsed successfully
	if user.TOTPSecret != "KVKVE43VNVSTSMKM" {
		t.Errorf("Expected TOTPSecret KVKVE43VNVSTSMKM, got %q", user.TOTPSecret)
	}
}

func TestSessionCookies(t *testing.T) {
	auth, err := NewAuthenticator("my-signing-secret")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	// Register user in memory first to pass existence checks
	auth.Users["admin"] = &User{
		Username: "admin",
		Role:     "admin",
	}

	// Create signed session cookie claiming admin role
	cookieVal, err := auth.CreateSessionCookie("admin", "admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateSessionCookie failed: %v", err)
	}

	// Verify session cookie
	sess, err := auth.VerifySessionCookie(cookieVal)
	if err != nil {
		t.Fatalf("VerifySessionCookie failed: %v", err)
	}
	if sess.Username != "admin" || sess.Role != "admin" {
		t.Errorf("Invalid session values: %+v", sess)
	}

	// Test immediate revocation: change role in-memory to viewer
	auth.Users["admin"].Role = "viewer"
	sessUpdated, err := auth.VerifySessionCookie(cookieVal)
	if err != nil {
		t.Fatalf("VerifySessionCookie failed after role update: %v", err)
	}
	if sessUpdated.Role != "viewer" {
		t.Errorf("Expected dynamically updated role viewer, got %s", sessUpdated.Role)
	}

	// Test immediate deletion: remove user from map
	delete(auth.Users, "admin")
	_, err = auth.VerifySessionCookie(cookieVal)
	if err == nil || err.Error() != "user no longer exists" {
		t.Errorf("Expected failure 'user no longer exists', got %v", err)
	}

	// Re-add user for remaining tests
	auth.Users["admin"] = &User{
		Username: "admin",
		Role:     "admin",
	}

	// Test tampering detection
	tamperedCookie := cookieVal + "extra"
	_, err = auth.VerifySessionCookie(tamperedCookie)
	if err == nil {
		t.Error("VerifySessionCookie succeeded with tampered signature")
	}

	// Test expired session cookie
	expiredCookieVal, err := auth.CreateSessionCookie("admin", "admin", -1*time.Second)
	if err != nil {
		t.Fatalf("Failed to create expired session cookie: %v", err)
	}

	_, err = auth.VerifySessionCookie(expiredCookieVal)
	if err == nil {
		t.Error("VerifySessionCookie succeeded for expired session")
	}
}

func TestFluentAuthenticator(t *testing.T) {
	// Test fluent creation
	auth := New().
		WithSessionSecret("secret-key").
		WithUser("alice", &User{
			Username:     "alice",
			PasswordHash: "$2a$10$UnFkQy4iVl3hKq4oFjP5FeW0H74U7Qh739L7y/8K4Z4G2hNl0V73y", // hash for "password"
			Role:         "admin",
			TOTPSecret:   "JBSWY3DPEHPK3PXP",
		})

	if auth.Error() != nil {
		t.Fatalf("Expected no config error, got %v", auth.Error())
	}

	if _, exists := auth.Users["alice"]; !exists {
		t.Fatal("Expected user alice to be registered")
	}

	// Test fluent logging
	auth.NewEvent("LOGIN_SUCCESS").
		ForUser("alice").
		FromIP("127.0.0.1").
		WithDetails("Alice logged in fluently").
		Log()

	events := auth.GetEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].Event != "LOGIN_SUCCESS" || events[0].Username != "alice" || events[0].IP != "127.0.0.1" || events[0].Details != "Alice logged in fluently" {
		t.Errorf("Unexpected event values: %+v", events[0])
	}
}

func TestSaveUserToGopassFile(t *testing.T) {
	tempDir := t.TempDir()
	auth, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	username := "bob"
	password := "bob-secure-pass"
	passphrase := "age-passphrase-xyz"
	role := "developer"
	totpSecret := "KVKVE43VNVSTSMKM"

	// Save user
	err = auth.SaveUserToGopassFile(tempDir, username, password, passphrase, role, totpSecret, "")
	if err != nil {
		t.Fatalf("SaveUserToGopassFile failed: %v", err)
	}

	// Verify Bob is now in memory
	u, ok := auth.Users[username]
	if !ok {
		t.Fatal("User bob was not registered in memory")
	}
	if u.Role != role || u.TOTPSecret != totpSecret {
		t.Errorf("Mismatch in registered memory user properties: %+v", u)
	}

	// Create a new fresh authenticator to simulate server restart and load Bob from disk
	auth2, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create second authenticator: %v", err)
	}

	// Load users from tempDir
	filePath := filepath.Join(tempDir, username+".age")
	encryptedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	err = auth2.LoadUserFromGopassContent(username, encryptedContent, passphrase, "")
	if err != nil {
		t.Fatalf("Failed to load user from encrypted file: %v", err)
	}

	// Verify authentication
	totpToken, err := totp.Generate(totpSecret, time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to generate TOTP token: %v", err)
	}

	u2, err := auth2.Authenticate(username, password, totpToken)
	if err != nil {
		t.Fatalf("Failed to authenticate Bob: %v", err)
	}
	if u2.Username != username || u2.Role != role {
		t.Errorf("User mismatch after authentication: %+v", u2)
	}
}

func TestVerifyMnemonicRecovery(t *testing.T) {
	tempDir := t.TempDir()
	auth, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	username := "charlie"
	password := "charlie-pass"
	passphrase := "age-passphrase-xyz"
	role := "viewer"
	totpSecret := "KVKVE43VNVSTSMKM"
	recoveryKey := "NATIVEBPM-REC-1234-5678-9012"

	// Save user with recovery key
	err = auth.SaveUserToGopassFile(tempDir, username, password, passphrase, role, totpSecret, recoveryKey)
	if err != nil {
		t.Fatalf("SaveUserToGopassFile with recovery key failed: %v", err)
	}

	// 1. Verify verification works on loaded in-memory user
	err = auth.VerifyMnemonicRecovery(username, password, recoveryKey)
	if err != nil {
		t.Errorf("VerifyMnemonicRecovery failed on in-memory user: %v", err)
	}

	// Verify verification works with clean normalized key containing hyphens and lowercase
	err = auth.VerifyMnemonicRecovery(username, password, "nativebpm-rec-1234-5678-9012")
	if err != nil {
		t.Errorf("VerifyMnemonicRecovery failed with normalized key: %v", err)
	}

	// Verify failure with wrong recovery key
	err = auth.VerifyMnemonicRecovery(username, password, "NATIVEBPM-REC-9999-9999-9999")
	if err == nil {
		t.Error("VerifyMnemonicRecovery succeeded with incorrect recovery key")
	}

	// Verify failure with wrong password
	err = auth.VerifyMnemonicRecovery(username, "wrong-pass", recoveryKey)
	if err == nil {
		t.Error("VerifyMnemonicRecovery succeeded with incorrect password")
	}

	// 2. Load from disk and verify it also reloads recovery key correctly
	auth2, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create second authenticator: %v", err)
	}

	filePath := filepath.Join(tempDir, username+".age")
	encryptedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	err = auth2.LoadUserFromGopassContent(username, encryptedContent, passphrase, "")
	if err != nil {
		t.Fatalf("Failed to load user from encrypted file: %v", err)
	}

	err = auth2.VerifyMnemonicRecovery(username, password, recoveryKey)
	if err != nil {
		t.Errorf("VerifyMnemonicRecovery failed on reloaded user: %v", err)
	}
}

func TestUpdateUserRoleAndGetUsers(t *testing.T) {
	tempDir := t.TempDir()
	auth, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	username := "daniel"
	password := "daniel-pass"
	passphrase := "age-passphrase-xyz"
	role := "viewer"
	totpSecret := "KVKVE43VNVSTSMKM"

	err = auth.SaveUserToGopassFile(tempDir, username, password, passphrase, role, totpSecret, "")
	if err != nil {
		t.Fatalf("SaveUserToGopassFile failed: %v", err)
	}

	// 1. Verify GetUsers returns loaded users
	users := auth.GetUsers()
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}
	if users[0].Username != username || users[0].Role != role {
		t.Errorf("Unexpected user in GetUsers output: %+v", users[0])
	}

	// 2. Update Role to developer
	err = auth.UpdateUserRole(tempDir, username, passphrase, "developer")
	if err != nil {
		t.Fatalf("UpdateUserRole failed: %v", err)
	}

	// Verify in-memory role is updated
	if auth.Users[username].Role != "developer" {
		t.Errorf("In-memory role not updated, got %s", auth.Users[username].Role)
	}

	// 3. Reload from disk to verify persistence
	auth2, err := NewAuthenticator("session-key-123")
	if err != nil {
		t.Fatalf("Failed to create second authenticator: %v", err)
	}

	filePath := filepath.Join(tempDir, username+".age")
	encryptedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	err = auth2.LoadUserFromGopassContent(username, encryptedContent, passphrase, "")
	if err != nil {
		t.Fatalf("Failed to load user: %v", err)
	}

	if auth2.Users[username].Role != "developer" {
		t.Errorf("Persisted role not updated, got %s", auth2.Users[username].Role)
	}
}

func TestVerifySupabaseJWT(t *testing.T) {
	jwtSecret := "my-supabase-jwt-secret-key-12345"
	auth := New().WithSupabase("https://my-supabase.supabase.co", jwtSecret)

	// Create a mock Supabase JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "user@example.com",
		"sub":   "a543b210-9876-4321-8765-abcdef012345",
		"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		"user_metadata": map[string]interface{}{
			"role": "developer",
		},
	})
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify the token using the authenticator
	sess, err := auth.VerifySessionCookie(tokenString)
	if err != nil {
		t.Fatalf("VerifySessionCookie failed to parse Supabase token: %v", err)
	}

	if sess.Username != "user@example.com" {
		t.Errorf("Expected username user@example.com, got %q", sess.Username)
	}
	if sess.Role != "developer" {
		t.Errorf("Expected role developer, got %q", sess.Role)
	}
}



func BenchmarkCreateSessionCookie(b *testing.B) {
	auth, _ := NewAuthenticator("my-signing-secret")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = auth.CreateSessionCookie("admin", "admin", 1*time.Hour)
	}
}

func BenchmarkVerifySessionCookie(b *testing.B) {
	auth, _ := NewAuthenticator("my-signing-secret")
	// Make sure the user is in-memory for local verify session check to pass
	auth.Users["admin"] = &User{
		Username: "admin",
		Role:     "admin",
	}
	cookieVal, _ := auth.CreateSessionCookie("admin", "admin", 1*time.Hour)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = auth.VerifySessionCookie(cookieVal)
	}
}

func BenchmarkVerifySessionCookieUncached(b *testing.B) {
	auth, _ := NewAuthenticator("my-signing-secret")
	auth.Users["admin"] = &User{
		Username: "admin",
		Role:     "admin",
	}
	cookieVal, _ := auth.CreateSessionCookie("admin", "admin", 1*time.Hour)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		auth.InvalidateAll()
		_, _ = auth.VerifySessionCookie(cookieVal)
	}
}

func TestSessionCacheHitsAndRevocation(t *testing.T) {
	auth, err := NewAuthenticator("my-signing-secret")
	if err != nil {
		t.Fatalf("Failed to create authenticator: %v", err)
	}

	auth.Users["user1"] = &User{
		Username: "user1",
		Role:     "developer",
	}

	cookieVal, err := auth.CreateSessionCookie("user1", "developer", 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateSessionCookie failed: %v", err)
	}

	// 1. Initial verification: cache miss, performs full verification
	sess1, err := auth.VerifySessionCookie(cookieVal)
	if err != nil {
		t.Fatalf("First VerifySessionCookie failed: %v", err)
	}

	// 2. Second verification: cache hit
	sess2, err := auth.VerifySessionCookie(cookieVal)
	if err != nil {
		t.Fatalf("Second VerifySessionCookie failed: %v", err)
	}

	if sess1.Username != sess2.Username || sess1.Role != sess2.Role {
		t.Errorf("Sessions do not match: %+v vs %+v", sess1, sess2)
	}

	// Verify it was actually cached
	hash := auth.hashToken(cookieVal)
	auth.cacheMu.RLock()
	cached, exists := auth.sessionCache[hash]
	auth.cacheMu.RUnlock()
	if !exists || cached.Session != sess2 {
		t.Errorf("Expected token to be cached under hash %s", hash)
	}

	// 3. Test revocation invalidates the cache entries of this user
	auth.InvalidateUserSessions("user1")

	auth.cacheMu.RLock()
	_, exists = auth.sessionCache[hash]
	auth.cacheMu.RUnlock()
	if exists {
		t.Errorf("Expected cached session to be evicted after user session invalidation")
	}
}
