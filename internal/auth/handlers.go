package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"authdemo/ent"
	"authdemo/ent/user"
)

const sessionTTL = 24 * time.Hour

// Handler holds what the HTTP handlers need: the database client.
type Handler struct {
	client *ent.Client
}

func NewHandler(c *ent.Client) *Handler { return &Handler{client: c} }

// credentials is the JSON body for both /register and /login.
// The `binding` tags are validation rules enforced by ShouldBindJSON.
type credentials struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8,max=72"` // bcrypt only uses the first 72 bytes
}

// newToken returns the raw token (given to the client) and its hash (stored in the DB).
func newToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Register creates a user. POST /register
func (h *Handler) Register(c *gin.Context) {
	var in credentials
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and a password of 8-72 characters are required"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	u, err := h.client.User.Create().
		SetEmail(email).
		SetPasswordHash(string(hash)).
		Save(c.Request.Context())
	if ent.IsConstraintError(err) { // unique index on email
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": u.ID, "email": u.Email})
}

// Login checks the password and starts a session. POST /login
func (h *Handler) Login(c *gin.Context) {
	var in credentials
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}
	ctx := c.Request.Context()
	email := strings.ToLower(strings.TrimSpace(in.Email))

	u, err := h.client.User.Query().Where(user.EmailEQ(email)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	// Same answer for "no such user" and "wrong password" so callers can't tell which.
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	raw, hash, err := newToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	_, err = h.client.Session.Create().
		SetTokenHash(hash).
		SetExpiresAt(time.Now().Add(sessionTTL)).
		SetUser(u).
		Save(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": raw, "expires_in": int(sessionTTL.Seconds())})
}

// Me returns the logged-in user. GET /me (needs RequireAuth)
func (h *Handler) Me(c *gin.Context) {
	s := c.MustGet(sessionKey).(*ent.Session)
	c.JSON(http.StatusOK, gin.H{"id": s.Edges.User.ID, "email": s.Edges.User.Email})
}

// Logout revokes the current session. POST /logout (needs RequireAuth)
func (h *Handler) Logout(c *gin.Context) {
	s := c.MustGet(sessionKey).(*ent.Session)
	err := h.client.Session.UpdateOneID(s.ID).SetRevokedAt(time.Now()).Exec(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "logged out"})
}
