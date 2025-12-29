package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"assurance_service/internal/audit"
	"assurance_service/internal/config"
	"assurance_service/internal/policy"
	"assurance_service/internal/server"
)

func main() {
	cfg := config.Load()

	store, err := audit.NewStore(cfg.DataDir, cfg.BatchSize)
	if err != nil {
		log.Fatalf("store init failed: %v", err)
	}

	engine, err := policy.Load("./policies/policy.json")
	if err != nil {
		log.Fatalf("policy load failed: %v", err)
	}

	handler := &server.Handler{
		Store:        store,
		Policy:       engine,
		SharedSecret: cfg.SharedSecret,
		EventsPath:   fmt.Sprintf("%s/events.log", cfg.DataDir),
		RootsPath:    fmt.Sprintf("%s/roots.log", cfg.DataDir),
		BatchSize:    cfg.BatchSize,
		KAnonymity:   cfg.KAnonymity,
		DPEpsilon:    cfg.DPEpsilon,
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      server.New(handler),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("Assurance service listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
