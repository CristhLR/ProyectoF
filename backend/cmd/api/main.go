package main

import (
	"log"
	"net/http"
	"os"

	"github.com/proyectof/backend/internal/app"
	"github.com/proyectof/backend/internal/config"
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

	server := app.NewServer(db, []byte(jwtSecret))
	handler := server.Router()

	addr := ":" + port
	log.Printf("starting http server on %s", addr)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("http server stopped: %v", err)
	}
}
