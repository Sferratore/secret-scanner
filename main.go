package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bl4ckw1ng/secret-scanner/api"
	"github.com/gin-gonic/gin"
)

// Config maps directly to config.json.
type Config struct {
	Port           string   `json:"port"`
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers"`
	ScanTimeoutSecs int     `json:"scan_timeout_secs"`
	MaxFileSizeMB  int      `json:"max_file_size_mb"`
}

func loadConfig(path string) Config {
	cfg := Config{
		Port:            "8080",
		AllowedOrigins:  []string{"*"},
		AllowedMethods:  []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:  []string{"Content-Type", "Authorization"},
		ScanTimeoutSecs: 300,
		MaxFileSizeMB:   1,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("No config file found at %s, using defaults", path)
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Invalid config file: %v", err)
	}
	log.Printf("Loaded config from %s", path)
	return cfg
}

func main() {
	cfg := loadConfig("config.json")

	router := gin.New()

	// ── Middleware ────────────────────────────────────────────────────────
	router.Use(gin.Recovery())
	router.Use(requestLogger())
	router.Use(corsMiddleware(cfg))

	// ── Routes ────────────────────────────────────────────────────────────
	router.GET("/health", api.HealthHandler)

	apiGroup := router.Group("/api")
	{
		apiGroup.POST("/scan", api.ScanHandler)
	}

	log.Printf("Secret Scanner API listening on :%s", cfg.Port)
	if err := router.Run(":" + cfg.Port); err != nil {
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

// corsMiddleware reads allowed origins/methods/headers from config.
func corsMiddleware(cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", strings.Join(cfg.AllowedOrigins, ", "))
		c.Header("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
