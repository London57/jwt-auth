package middleware

import (
	"net/http"
	"strings"

	"github.com/London57/auth-jwt/jwtutil"
	"github.com/gin-gonic/gin"
)

type error struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

const UserID = "userID"

func JwtAuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		s := strings.Split(authHeader, " ")
		if len(s) == 2 {
			authToken := s[1]
			authorized, err := jwtutil.IsAuthorized(authToken, secret)
			if authorized {
				userID, err := jwtutil.ExtractIDFromToken(authToken, secret)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusUnauthorized, error{
						Message: "failed to get ID from token",
						Details: err.Error(),
					})
					return
				}
				c.Set("userID", userID)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, error{
				Message: "len authorazion header 2, but error",
				Details: err.Error(),
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, error{
			Message: "Not authorized",
			Details: "",})
	}
}