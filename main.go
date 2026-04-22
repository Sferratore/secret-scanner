package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bl4ckw1ng/secret-scanner/api"
	"github.com/bl4ckw1ng/secret-scanner/models"
	"github.com/gin-gonic/gin"
)

// Config maps directly to config.json.
type Config struct {
	Port            string   `json:"port"`
	AllowedOrigins  []string `json:"allowed_origins"`
	AllowedMethods  []string `json:"allowed_methods"`
	AllowedHeaders  []string `json:"allowed_headers"`
	ScanTimeoutSecs int      `json:"scan_timeout_secs"`
	MaxFileSizeMB   int      `json:"max_file_size_mb"`
	RateLimit       int      `json:"rate_limit"`       // max requests per window per IP
	RateWindowSecs  int      `json:"rate_window_secs"` // window duration in seconds
}

func loadConfig(path string) Config {
	cfg := Config{
		Port:            "8080",
		AllowedOrigins:  []string{"*"},
		AllowedMethods:  []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:  []string{"Content-Type", "Authorization"},
		ScanTimeoutSecs: 300,
		MaxFileSizeMB:   1,
		RateLimit:       5,
		RateWindowSecs:  60,
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
		apiGroup.POST("/scan", rateLimiter(cfg), api.ScanHandler)
	}

	// Explicit http.Server with timeouts on every phase. Gin's router.Run
	// uses Go's defaults (no timeouts), which leaves the process open to
	// slowloris-style attacks: a client trickling headers or reading the
	// response one byte at a time holds a goroutine and a connection
	// indefinitely, bypassing both the per-IP rate limiter and the scan
	// semaphore (those only apply once the handler runs).
	//
	// WriteTimeout must outlast api.scanTimeout (5m) plus the queue wait
	// budget (10s), since the response is written after the scan returns.
	// 5m30s gives a safety margin for the handler's own JSON encode.
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5*time.Minute + 30*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Secret Scanner API listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil {
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

// rateLimiter tracks requests per IP using a sliding window.
func rateLimiter(cfg Config) gin.HandlerFunc {
	type visitor struct {
		count    int
		windowStart time.Time
	}

	var mu sync.Mutex
	visitors := make(map[string]*visitor)
	window := time.Duration(cfg.RateWindowSecs) * time.Second

	// Clean up stale entries every window duration
	go func() {
		for {
			time.Sleep(window)
			mu.Lock()
			for ip, v := range visitors {
				if time.Since(v.windowStart) > window {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		v, exists := visitors[ip]
		now := time.Now()

		if !exists || now.Sub(v.windowStart) > window {
			// New window
			visitors[ip] = &visitor{count: 1, windowStart: now}
			mu.Unlock()
			c.Next()
			return
		}

		v.count++
		if v.count > cfg.RateLimit {
			mu.Unlock()
			c.JSON(http.StatusTooManyRequests, models.ErrorResponse{
				Error: "rate limit exceeded, try again later",
			})
			c.Abort()
			return
		}

		mu.Unlock()
		c.Next()
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
