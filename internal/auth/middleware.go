package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"authdemo/ent/session"
)

// sessionKey is where RequireAuth stores the session on the Gin context
// so later handlers (Me, Logout) can read it.
const sessionKey = "auth.session"

// RequireAuth accepts only requests with "Authorization: Bearer <token>"
// whose session exists, is not revoked and has not expired.
func (h *Handler) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok || raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		s, err := h.client.Session.Query().
			Where(
				session.TokenHashEQ(hashToken(raw)),
				session.RevokedAtIsNil(),
				session.ExpiresAtGT(time.Now()),
			).
			WithUser(). // eager-load the user (like Django's select_related)
			Only(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set(sessionKey, s)
		c.Next()
	}
}
