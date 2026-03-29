package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

func main() {
	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	configDir := filepath.Dir(configPath)
	if configDir == "" {
		configDir = "."
	}

	pipeline, sessions, err := BuildPipeline(cfg, configDir)
	if err != nil {
		slog.Error("failed to build pipeline", "err", err)
		os.Exit(1)
	}

	if err := RunServer(cfg, pipeline, sessions, os.Getenv("API_KEY")); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
