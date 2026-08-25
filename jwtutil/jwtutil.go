package jwtutil

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)


type Jwt interface {
	CreateAccessToken(id uuid.UUID, username string, secret string, expiry int) (string, error)
	CreateRefreshToken(id uuid.UUID, secret string, expiry int) (string, error)
	RefreshAccessToken(refresh string) (string, string, error)
}

type JwtImpl struct {
	secret string
	accessExp int
	refreshExp int
}

func (j JwtImpl) CreateAccessToken(id uuid.UUID, username string) (string, error) {
	exp := time.Now().Add(time.Hour * time.Duration(j.accessExp))
	claims := &JwtCustomClaims{
		ID:       id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(j.secret))
	if err != nil {
		return "", fmt.Errorf("failed to signed jwt: %w", err)
	}
	return t, nil
}
	
func (j JwtImpl) CreateRefreshToken(id uuid.UUID) (string, error) {
	exp := time.Now().Add(time.Hour * time.Duration(j.refreshExp))
	claimsRefresh := &JwtCustomRefreshClaims{
		ID: id,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	t, err := token.SignedString([]byte(j.secret))
	if err != nil {

		return "", fmt.Errorf("failed to signed jwt: %w", err)
	}
	return t, nil
}

func IsAuthorized(token string, secret string) (bool, error) {
	_, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sighing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		jwt_error := err.(jwt.ValidationError)

		if jwt_error.Errors&jwt.ValidationErrorExpired != 0 {
			return false, errors.New("token expired")
		}
		return false, fmt.Errorf("failed to parse jwt: %v", err)
	}
	return true, nil
}

func (j JwtImpl) IsAuthorized(token string) (bool, error) {
	_, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sighing method: %v", token.Header["alg"])
		}
		return []byte(j.secret), nil
	})
	if err != nil {
		jwt_error := err.(jwt.ValidationError)

		if jwt_error.Errors&jwt.ValidationErrorExpired != 0 {
			return false, errors.New("token expired")
		}
		return false, fmt.Errorf("failed to parse jwt: %v", err)
	}
	return true, nil
}

func ExtractFieldFromToken(requestToken string, secret string, field string) (string, error) {
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sighing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse jwt: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}
	if claims[field] == nil { 
		return "", errors.New("field not found")
	}
	return claims[field].(string), nil
}

func (j JwtImpl) ExtractFieldFromToken(requestToken string, field string) (string, error) {
	token, err := jwt.Parse(requestToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected sighing method: %v", token.Header["alg"])
		}
		return []byte(j.secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse jwt: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("token is invalid")
	}
	if claims[field] == nil { 
		return "", errors.New("field not found")
	}
	return claims[field].(string), nil
}

func (j JwtImpl) RefreshAccessToken(access, refresh string) (string, string, error) {
	authorised, err := j.IsAuthorized(refresh)
	if err != nil {
		return "", "", err
	}
	if !authorised {
		return "", "", errors.New("you are not authorised") 
	}

	id, err := j.ExtractFieldFromToken(refresh, "id")
	if err != nil {
		return "", "", err
	}

	claims := &JwtCustomClaims{}
	parser := jwt.Parser{}
	_, _, err = parser.ParseUnverified(access, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse data from token, %w", err)
	}

	if claims.ID.String() != id {
		return "", "", errors.New("tokens belong to different users")
	}
	access_token, err := j.CreateAccessToken(claims.ID, claims.Username)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token: %w", err)
	}

	refresh_token, err := j.CreateRefreshToken(claims.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to create access token: %w", err)
	}
	return access_token, refresh_token, nil
}