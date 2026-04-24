package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"

	db "proxy-gateway/db/gen"
)

func main() {
	initLogging(os.Getenv("LOG_LEVEL"))

	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Config file's log_level applies only when no LOG_LEVEL env var was set.
	// Env var wins so operators can flip debug on/off without editing config.
	if os.Getenv("LOG_LEVEL") == "" && cfg.LogLevel != "" {
		initLogging(cfg.LogLevel)
	}

	configDir := filepath.Dir(configPath)
	if configDir == "" {
		configDir = "."
	}

	// --- Database (optional) ---
	var tracker *UsageTracker
	var queries *db.Queries
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		pool, err := pgxpool.New(context.Background(), dsn)
		if err != nil {
			slog.Error("failed to connect to database", "err", err)
			os.Exit(1)
		}
		queries = db.New(pool)
		tracker = NewUsageTracker(queries)
		slog.Info("usage tracking enabled")
	} else {
		slog.Info("DATABASE_URL not set, usage tracking disabled")
	}

	srv, err := BuildServer(cfg, configDir, os.Getenv("PROXY_PASSWORD"), tracker, queries)
	if err != nil {
		slog.Error("failed to build server", "err", err)
		os.Exit(1)
	}

	if err := RunServer(cfg, srv, os.Getenv("API_KEY")); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func initLogging(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
