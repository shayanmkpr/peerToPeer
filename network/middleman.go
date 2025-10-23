package network

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"time"
)

// ResponseWriter wrapper to capture status code and response size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // default status
	}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// TrafficMonitor logs all incoming requests and outgoing responses
func TrafficMonitor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log incoming request
		log.Printf(">>> [INCOMING] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		log.Printf("    Headers: %v", r.Header)
		log.Printf("    Query Params: %v", r.URL.RawQuery)

		// Read and log request body (if exists)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			// Restore the body so the actual handler can read it
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			if len(bodyBytes) > 0 {
				log.Printf("    Body: %s", string(bodyBytes))
			}
		}

		// Wrap the response writer to capture status code and size
		wrappedWriter := newResponseWriter(w)

		// Process the request
		next.ServeHTTP(wrappedWriter, r)

		// Log outgoing response
		duration := time.Since(start)
		log.Printf("<<< [OUTGOING] %s %s - Status: %d - Size: %d bytes - Duration: %v",
			r.Method, r.URL.Path, wrappedWriter.statusCode, wrappedWriter.size, duration)
		log.Println("---")
	})
}

// SecurityMonitor checks for suspicious patterns
func SecurityMonitor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for suspicious patterns
		suspiciousPatterns := []string{"../", "<script>", "DROP TABLE", "SELECT *"}

		fullURL := r.URL.Path + "?" + r.URL.RawQuery
		for _, pattern := range suspiciousPatterns {
			if contains(fullURL, pattern) || contains(r.Header.Get("User-Agent"), pattern) {
				log.Printf("⚠️  [SECURITY ALERT] Suspicious pattern '%s' detected in request from %s",
					pattern, r.RemoteAddr)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// PerformanceMonitor tracks slow endpoints
func PerformanceMonitor(threshold time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			next.ServeHTTP(w, r)

			duration := time.Since(start)
			if duration > threshold {
				log.Printf("⚠️  [PERFORMANCE] Slow endpoint detected: %s %s took %v (threshold: %v)",
					r.Method, r.URL.Path, duration, threshold)
			}
		})
	}
}

// RateLimitMonitor tracks request frequency per IP (basic implementation)
func RateLimitMonitor(next http.Handler) http.Handler {
	requestCounts := make(map[string]int)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		requestCounts[ip]++

		if requestCounts[ip] > 100 { // Simple threshold
			log.Printf("⚠️  [RATE LIMIT] High request count from %s: %d requests",
				ip, requestCounts[ip])
		}

		next.ServeHTTP(w, r)
	})
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				hasSubstring(s, substr)))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
