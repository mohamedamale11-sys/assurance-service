package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port         int
	DataDir      string
	SharedSecret string
	BatchSize    int
	KAnonymity   int
	DPEpsilon    float64
	DPSeed       int64
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
}

func Load() Config {
	getInt := func(key string, def int) int {
		val := os.Getenv(key)
		if val == "" {
			return def
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			log.Fatalf("invalid %s=%q", key, val)
		}
		return n
	}
	getFloat := func(key string, def float64) float64 {
		val := os.Getenv(key)
		if val == "" {
			return def
		}
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			log.Fatalf("invalid %s=%q", key, val)
		}
		return f
	}
	getDuration := func(key string, def time.Duration) time.Duration {
		val := os.Getenv(key)
		if val == "" {
			return def
		}
		d, err := time.ParseDuration(val)
		if err != nil {
			log.Fatalf("invalid %s=%q", key, val)
		}
		return d
	}

	cfg := Config{
		Port:         getInt("ASSURE_PORT", 9010),
		DataDir:      os.Getenv("ASSURE_DATA_DIR"),
		SharedSecret: os.Getenv("ASSURE_SHARED_SECRET"),
		BatchSize:    getInt("ASSURE_BATCH_SIZE", 100),
		KAnonymity:   getInt("ASSURE_K_ANON", 5),
		DPEpsilon:    getFloat("ASSURE_DP_EPS", 0.7),
		DPSeed:       int64(getInt("ASSURE_DP_SEED", 0)),
		WriteTimeout: getDuration("ASSURE_WRITE_TIMEOUT", 5*time.Second),
		ReadTimeout:  getDuration("ASSURE_READ_TIMEOUT", 5*time.Second),
	}

	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.KAnonymity <= 1 {
		cfg.KAnonymity = 2
	}
	if cfg.DPEpsilon <= 0 {
		cfg.DPEpsilon = 0.7
	}
	return cfg
}
