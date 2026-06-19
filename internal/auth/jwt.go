package auth

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

func ParseUserID(subject string) (int64, error) {
	var userID int64
	_, err := fmt.Sscanf(subject, "%d", &userID)
	return userID, err
}

const jwtSecretName = "jwt_secret"

const ContextKeyClaims = "claims"

type Claims struct {
	jwt.RegisteredClaims
}

type JWTService struct {
	secret []byte
}

func NewJWTService(db *sql.DB) (*JWTService, error) {
	secret, err := loadJWTSecret(db)
	if err != nil {
		return nil, err
	}
	return &JWTService{secret: secret}, nil
}

func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (s *JWTService) UserIDFromCookie(r *http.Request) (int64, error) {
	cookie, err := r.Cookie("token")
	if err != nil || cookie.Value == "" {
		return 0, fmt.Errorf("missing token cookie")
	}
	claims, err := s.ValidateToken(cookie.Value)
	if err != nil {
		return 0, fmt.Errorf("invalid token: %w", err)
	}
	return ParseUserID(claims.Subject)
}

func (s *JWTService) GenerateToken(userID int64) (string, error) {
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			Issuer:    "auth",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func loadJWTSecret(db *sql.DB) ([]byte, error) {
	var secret []byte
	err := db.QueryRow("SELECT value FROM secrets WHERE name = ?", jwtSecretName).Scan(&secret)
	if err == nil {
		return secret, nil
	}

	log.Info().Msg("no previous jwt secret found, generating new secret")
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate jwt secret: %w", err)
	}

	_, err = db.Exec("INSERT INTO secrets (name, value) VALUES (?, ?)", jwtSecretName, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to store jwt secret: %w", err)
	}

	return secret, nil
}
