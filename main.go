package main

import (
	"log"
	"time"

	"github.com/bl4ckw1ng/secret-scanner/api"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.New()

	// ── Middleware ────────────────────────────────────────────────────────
	router.Use(gin.Recovery())
	router.Use(requestLogger())
	router.Use(corsMiddleware())

	// ── Routes ────────────────────────────────────────────────────────────
	router.GET("/health", api.HealthHandler)

	apiGroup := router.Group("/api")
	{
		apiGroup.POST("/scan", api.ScanHandler)
	}

	log.Println("Secret Scanner API listening on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// requestLogger logs each request with method, path, status, and latency.
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("[%s] %s %s | %d | %s",
			time.Now().Format(time.RFC3339),
			c.Request.Method,
			c.Request.URL.Path,
			c.Writer.Status(),
			time.Since(start),
		)
	}
}

// corsMiddleware allows all origins (suitable for development/internal use).
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
