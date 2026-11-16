package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // registers the "postgres" driver (side-effect import)

	"authdemo/ent"
	"authdemo/internal/auth"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5433/authdemo?sslmode=disable"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client, err := ent.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer client.Close()

	h := auth.NewHandler(client)

	r := gin.Default()

	// Health: proves the server is up and the database is reachable.
	r.GET("/health", func(c *gin.Context) {
		n, err := client.User.Query().Count(c.Request.Context())
		if err != nil {
			c.JSON(500, gin.H{"error": "database unreachable"})
			return
		}
		c.JSON(200, gin.H{"status": "ok", "users": n})
	})

	// Public routes.
	r.POST("/register", h.Register)
	r.POST("/login", h.Login)

	// Protected routes: RequireAuth runs first, then the handler.
	r.GET("/me", h.RequireAuth(), h.Me)
	r.POST("/logout", h.RequireAuth(), h.Logout)

	log.Fatal(r.Run(":" + port))
}
