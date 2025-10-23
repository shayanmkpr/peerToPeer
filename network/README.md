# JWT Authentication System

Production-ready JWT authentication for Go with security best practices built-in.

## How It Works

### Token Strategy
We use **two types of tokens** for security and convenience:

- **Access Token** (15 min) - Short-lived, used for API requests
- **Refresh Token** (7 days) - Long-lived, used to get new access tokens

### Authentication Flow
```
1. User logs in → Server verifies password
2. Server generates access + refresh tokens
3. Client stores tokens
4. Client sends access token with each request
5. When access token expires → use refresh token to get new pair
```

## Quick Start

### 1. Install Dependencies
```bash
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
```

### 2. Set Environment Variables
```bash
export JWT_ACCESS_SECRET="your-random-secret-min-32-characters"
export JWT_REFRESH_SECRET="different-random-secret-min-32-characters"
```

### 3. Initialize Auth Service
```go
authService, err := NewAuthService(
    os.Getenv("JWT_ACCESS_SECRET"),
    os.Getenv("JWT_REFRESH_SECRET"),
)
```

### 4. Registration Endpoint
```go
func Register(w http.ResponseWriter, r *http.Request) {
    // Hash the password
    hashedPwd, err := authService.HashPassword(password)
    
    // Save user with hashedPwd to database
    // ...
}
```

### 5. Login Endpoint
```go
func Login(w http.ResponseWriter, r *http.Request) {
    // Get user from database
    // Verify password
    err := authService.VerifyPassword(user.HashedPassword, password)
    
    // Generate tokens
    access, refresh, _ := authService.GenerateTokenPair(user.ID, user.Email)
    
    // Return to client
    json.NewEncoder(w).Encode(map[string]string{
        "access_token":  access,
        "refresh_token": refresh,
    })
}
```

### 6. Protect Routes
```go
// Wrap protected routes with middleware
http.Handle("/api/profile", 
    authService.AuthMiddleware(http.HandlerFunc(ProfileHandler)))
```

### 7. Access User Info in Handlers
```go
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
    claims, _ := GetClaimsFromContext(r.Context())
    
    // Use claims.UserID and claims.Email
    userID := claims.UserID
}
```

### 8. Refresh Token Endpoint
```go
func Refresh(w http.ResponseWriter, r *http.Request) {
    // Validate refresh token
    claims, err := authService.ValidateRefreshToken(refreshToken)
    
    // Generate new pair
    access, refresh, _ := authService.GenerateTokenPair(claims.UserID, claims.Email)
    
    // Return new tokens
}
```

## Client Usage

### Making Authenticated Requests
```javascript
// Include access token in Authorization header
fetch('/api/profile', {
    headers: {
        'Authorization': `Bearer ${accessToken}`
    }
})
```

### Handling Token Expiration
```javascript
// When access token expires (401 error)
// Use refresh token to get new pair
const response = await fetch('/api/refresh', {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken })
})
```

## Security Features

✅ **Bcrypt password hashing** (cost 12)  
✅ **Short-lived access tokens** (15 min)  
✅ **Separate signing secrets** for each token type  
✅ **Algorithm verification** (prevents JWT attacks)  
✅ **Cryptographically secure random** token IDs  
✅ **Refresh token rotation** support (via JTI)

## Production Checklist

Before deploying to production:

- [ ] Store secrets in environment variables (never in code)
- [ ] Use HTTPS for all endpoints
- [ ] Add rate limiting on login/register endpoints
- [ ] Store refresh tokens in database for revocation
- [ ] Implement token blacklist on logout
- [ ] Add logging for failed login attempts
- [ ] Consider adding 2FA for sensitive operations
- [ ] Use secure httpOnly cookies for web clients

## Optional: Refresh Token Storage

For enhanced security, store refresh tokens in your database:

```go
type RefreshToken struct {
    JTI       string    // From JWT claims.ID
    UserID    string
    ExpiresAt time.Time
    Revoked   bool
}
```

This enables:
- Logout functionality (revoke token)
- Session management
- Detecting compromised tokens

## Troubleshooting

**"Invalid token"** - Check Authorization header format: `Bearer <token>`  
**"Token expired"** - Use refresh token to get new access token  
**Password hash fails** - Ensure password is at least 8 characters

## Architecture

```go
// Token contains these claims
type Claims struct {
    UserID string              // Your user identifier
    Email  string              // User email
    jwt.RegisteredClaims       // Expiration, issued at, etc.
}
```

The middleware automatically validates tokens and adds claims to the request context for easy access in your handlers.

## Token Lifetimes

| Token | Duration | Used For |
|-------|----------|----------|
| Access | 15 min | API requests |
| Refresh | 7 days | Getting new access tokens |

Adjust these constants in `auth.go` based on your security needs.
