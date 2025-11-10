package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/proyectof/backend/internal/config"
	"github.com/proyectof/backend/internal/models"
)

const (
	queueKey          = "queue:transmutaciones"
	notificationsChan = "notifications:transmutaciones"
)

func main() {
	ctx := context.Background()

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Fatal("REDIS_URL environment variable is required")
	}

	redisOpts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("parse redis url: %v", err)
	}

	redisClient := redis.NewClient(redisOpts)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("connect redis: %v", err)
	}

	db, err := config.InitDatabase()
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	log.Println("worker started, waiting for transmutaciones")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				if err := checkMisiones(ctx, db); err != nil {
					log.Printf("check misiones error: %v", err)
				}
				if err := checkMateriales(ctx, db); err != nil {
					log.Printf("check materiales error: %v", err)
				}
				if err := checkTransmutaciones(ctx, db); err != nil {
					log.Printf("check transmutaciones error: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		if err := processNext(ctx, db, redisClient); err != nil {
			log.Printf("process error: %v", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func processNext(ctx context.Context, db *gorm.DB, redisClient *redis.Client) error {
	result, err := redisClient.BLPop(ctx, 0, queueKey).Result()
	if err != nil {
		return fmt.Errorf("pop queue: %w", err)
	}

	if len(result) != 2 {
		return errors.New("unexpected queue payload")
	}

	idStr := result[1]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return fmt.Errorf("invalid transmutacion id %q: %w", idStr, err)
	}

	var transmutacion models.Transmutacion
	if err := db.WithContext(ctx).First(&transmutacion, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("transmutacion %d not found", id)
			return nil
		}
		return fmt.Errorf("load transmutacion: %w", err)
	}

	if err := updateEstado(ctx, db, &transmutacion, models.EstadoTransmutacionProcesando); err != nil {
		return err
	}

	if err := updateEstado(ctx, db, &transmutacion, models.EstadoTransmutacionAprobada); err != nil {
		return err
	}

	audit := models.Auditoria{
		Tipo:    "transmutaciones_process",
		Detalle: fmt.Sprintf("Transmutación %d aprobada", transmutacion.ID),
	}
	if err := db.WithContext(ctx).Create(&audit).Error; err != nil {
		return fmt.Errorf("create audit: %w", err)
	}

	if err := redisClient.Publish(ctx, notificationsChan, strconv.Itoa(int(transmutacion.ID))).Err(); err != nil {
		log.Printf("publish notification: %v", err)
	}

	log.Printf("transmutacion %d aprobada", transmutacion.ID)
	return nil
}

func updateEstado(ctx context.Context, db *gorm.DB, transmutacion *models.Transmutacion, estado string) error {
	if transmutacion.Estado == estado {
		return nil
	}

	transmutacion.Estado = estado
	if err := db.WithContext(ctx).Save(transmutacion).Error; err != nil {
		return fmt.Errorf("update estado: %w", err)
	}
	return nil
}
