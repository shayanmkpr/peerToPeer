package network

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Security Configuration
const (
	AccessTokenDuration  = 15 * time.Minute
	RefreshTokenDuration = 7 * 24 * time.Hour
	BcryptCost           = 12
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// Claims structure for JWT tokens
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// AuthService handles authentication operations
type AuthService struct {
	accessSecret  []byte
	refreshSecret []byte
}

// NewAuthService creates a new auth service with secure random secrets
// In production, load these from environment variables or secure vault
func NewAuthService(accessSecret, refreshSecret string) (*AuthService, error) {
	if len(accessSecret) < 32 || len(refreshSecret) < 32 {
		return nil, errors.New("secrets must be at least 32 characters")
	}

	return &AuthService{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
	}, nil
}

// HashPassword securely hashes a password using bcrypt
func (a *AuthService) HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword compares a hashed password with plaintext
func (a *AuthService) VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateTokenPair creates both access and refresh tokens
func (a *AuthService) GenerateTokenPair(userID, email string) (accessToken, refreshToken string, err error) {
	// Generate access token
	accessToken, err = a.generateToken(userID, email, AccessTokenDuration, a.accessSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token with unique JTI
	jti, err := generateSecureRandomString(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate jti: %w", err)
	}

	refreshToken, err = a.generateTokenWithJTI(userID, email, RefreshTokenDuration, a.refreshSecret, jti)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// generateToken creates a JWT token
func (a *AuthService) generateToken(userID, email string, duration time.Duration, secret []byte) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "your-app-name",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// generateTokenWithJTI creates a JWT token with a unique identifier
func (a *AuthService) generateTokenWithJTI(userID, email string, duration time.Duration, secret []byte, jti string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "your-app-name",
			ID:        jti, // Unique token ID for refresh token rotation
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ValidateAccessToken validates and parses an access token
func (a *AuthService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return a.validateToken(tokenString, a.accessSecret)
}

// ValidateRefreshToken validates and parses a refresh token
func (a *AuthService) ValidateRefreshToken(tokenString string) (*Claims, error) {
	return a.validateToken(tokenString, a.refreshSecret)
}

// validateToken validates and parses a JWT token
func (a *AuthService) validateToken(tokenString string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// Middleware for protecting routes
func (a *AuthService) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check Bearer scheme
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		// Validate token
		claims, err := a.ValidateAccessToken(parts[1])
		if err != nil {
			if errors.Is(err, ErrExpiredToken) {
				http.Error(w, "token expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaimsFromContext retrieves claims from request context
func GetClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value("claims").(*Claims)
	if !ok {
		return nil, errors.New("claims not found in context")
	}
	return claims, nil
}

// generateSecureRandomString generates a cryptographically secure random string
func generateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
