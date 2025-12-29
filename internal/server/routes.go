package server

import (
	"log"
	"net/http"
)

func New(handler *Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.Health)
	mux.HandleFunc("/events", handler.IngestEvent)
	mux.HandleFunc("/audit/root/latest", handler.LatestRoot)
	mux.HandleFunc("/audit/verify", handler.VerifyAudit)
	mux.HandleFunc("/audit/events", handler.ListEvents)
	mux.HandleFunc("/policy/check", handler.PolicyCheck)
	mux.HandleFunc("/privacy/tokens", handler.PrivacyTokenSummary)

	return logging(mux)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
