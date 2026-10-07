package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/London57/jwt-auth/jwtutil"
	"github.com/gin-gonic/gin"
)

type error struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

const UserID = "userID"

func JwtAuthMiddlewareWithFields(access_secret string, fields []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		s := strings.Split(authHeader, " ")
		if len(s) == 2 {
			authToken := s[1]
			authorized, err := jwtutil.IsAuthorized(authToken, access_secret)
			if authorized {
				for _, v := range fields {
					userID, err := jwtutil.ExtractFieldFromToken(authToken, access_secret, v)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusUnauthorized, error{
							Message: fmt.Sprintf("failed to get %s from token", v),
							Details: err.Error(),
						})
						c.Set(v, userID)
						return
					}
				}
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
			Details: ""})
	}
}

func JwtAuthMiddleware(access_secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		s := strings.Split(authHeader, " ")
		if len(s) == 2 {
			authToken := s[1]
			authorized, err := jwtutil.IsAuthorized(authToken, access_secret)
			if authorized {
				userID, err := jwtutil.ExtractFieldFromToken(authToken, access_secret, "userID")
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
			Details: ""})
	}
}
