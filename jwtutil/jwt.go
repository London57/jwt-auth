package jwtutil

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type (
	JwtCustomClaims struct {
		jwt.RegisteredClaims
		ID       uuid.UUID `json:"id"`
		Username string `json:"username"`
	}
	JwtCustomRefreshClaims struct {
		jwt.RegisteredClaims
		ID uuid.UUID `json:"id"`
	}
)