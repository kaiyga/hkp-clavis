package main

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

var rwPool = sync.Pool{
	New: func() any {
		return &responseWriter{}
	},
}

// LogMiddleware
func LogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := rwPool.Get().(*responseWriter)
		defer func() {
			rw.ResponseWriter = nil
			rwPool.Put(rw)
		}()

		rw.ResponseWriter = w
		// rw.statusCode = http.StatusOK

		next.ServeHTTP(rw, r)

		Logger.Info("request handled",
			slog.String("ip", getIP(r)),
			slog.String("method", r.Method),
			slog.Int("status", rw.statusCode),
			slog.String("path", r.URL.Path),
			slog.Duration("duration", time.Since(start)),
		)
	})
}
func getIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if i := strings.Index(forwarded, ","); i != -1 {
			return forwarded[:i]
		}
		return forwarded
	}
	return r.RemoteAddr
}
