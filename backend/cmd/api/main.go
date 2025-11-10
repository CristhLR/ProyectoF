package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/proyectof/backend/internal/app"
	"github.com/proyectof/backend/internal/config"
	"github.com/redis/go-redis/v9"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	db, err := config.InitDatabase()
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Fatal("REDIS_URL environment variable is required")
	}

	redisOpts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("parse redis url: %v", err)
	}

	redisClient := redis.NewClient(redisOpts)
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("connect redis: %v", err)
	}
	defer func() {
		_ = redisClient.Close()
	}()

	server := app.NewServer(db, []byte(jwtSecret), redisClient)
	handler := server.Router()

	addr := ":" + port
	log.Printf("starting http server on %s", addr)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("http server stopped: %v", err)
	}
}
