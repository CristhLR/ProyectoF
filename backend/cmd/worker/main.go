// cmd/worker/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/proyectof/backend/internal/models"
)

const (
	redisQueueKey        = "queue:transmutaciones"
	redisNotificationsCh = "notifications:transmutaciones"
)

// =====================
// main
// =====================

func main() {
	// 1) contexto raíz
	ctx := context.Background()

	// 2) conectar a la base
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN no está definido")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("no se pudo conectar a la base de datos: %v", err)
	}

	// 3) conectar a redis
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://redis:6379/0"
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("no se pudo parsear REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opt)

	log.Println("worker started, waiting for transmutaciones")

	// 4) goroutine que consume la cola
	go consumeQueue(ctx, db, rdb)

	// 5) goroutine que hace verificaciones periódicas
	go startPeriodicChecks(ctx, db, rdb)

	// 6) bloquear
	select {}
}

// =====================
// cola de transmutaciones
// =====================

func consumeQueue(ctx context.Context, db *gorm.DB, rdb *redis.Client) {
	for {
		// BLPop bloqueante
		res, err := rdb.BLPop(ctx, 0*time.Second, redisQueueKey).Result()
		if err != nil {
			log.Printf("error leyendo cola de redis: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if len(res) < 2 {
			continue
		}

		idStr := res[1]
		if err := processTransmutation(ctx, db, rdb, idStr); err != nil {
			log.Printf("error procesando transmutacion %s: %v", idStr, err)
		}
	}
}

func processTransmutation(ctx context.Context, db *gorm.DB, rdb *redis.Client, idStr string) error {
	var trans models.Transmutacion
	if err := db.WithContext(ctx).First(&trans, idStr).Error; err != nil {
		return fmt.Errorf("no se encontró la transmutación %s: %w", idStr, err)
	}

	// si ya estaba aprobada o rechazada, no hacemos nada
	if trans.Estado == models.EstadoTransmutacionAprobada || trans.Estado == models.EstadoTransmutacionRechazada {
		return nil
	}

	// marcar como aprobada
	trans.Estado = models.EstadoTransmutacionAprobada
	if err := db.WithContext(ctx).Save(&trans).Error; err != nil {
		return fmt.Errorf("no se pudo actualizar la transmutación %s: %w", idStr, err)
	}

	// registrar auditoría automática
	audit := models.Auditoria{
		Tipo:    "transmutaciones_worker",
		Detalle: fmt.Sprintf("Transmutación %d aprobada automáticamente por worker.", trans.ID),
	}
	if err := db.WithContext(ctx).Create(&audit).Error; err != nil {
		log.Printf("no se pudo guardar auditoría: %v", err)
	}

	// notificar por redis para que el WS del backend lo mande al front
	if err := rdb.Publish(ctx, redisNotificationsCh, fmt.Sprintf("%d", trans.ID)).Err(); err != nil {
		log.Printf("error publicando notificación redis: %v", err)
	}

	log.Printf("transmutación %d procesada por worker", trans.ID)
	return nil
}

// =====================
// verificaciones periódicas
// =====================

func startPeriodicChecks(ctx context.Context, db *gorm.DB, rdb *redis.Client) {
	// por defecto, cada 24h
	interval := 24 * time.Hour

	// pero si nos dan VERIFY_INTERVAL en segundos, lo usamos (útil para demo)
	if v := os.Getenv("VERIFY_INTERVAL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}

	log.Printf("verificador periódico iniciado, intervalo: %s", interval.String())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// correr una vez al inicio para que se vea
	if err := runChecksOnce(ctx, db); err != nil {
		log.Printf("error en verificación inicial: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := runChecksOnce(ctx, db); err != nil {
				log.Printf("error en verificación periódica: %v", err)
			}
		}
	}
}

func runChecksOnce(ctx context.Context, db *gorm.DB) error {
	// 1) materiales con poco stock
	if err := checkLowStock(ctx, db); err != nil {
		return err
	}

	// 2) misiones sin cerrar hace más de 24h
	if err := checkStaleMissions(ctx, db); err != nil {
		return err
	}

	return nil
}

func checkLowStock(ctx context.Context, db *gorm.DB) error {
	var materiales []models.Material
	if err := db.WithContext(ctx).Where("stock < ?", 3).Order("id asc").Find(&materiales).Error; err != nil {
		return fmt.Errorf("no se pudieron leer materiales: %w", err)
	}

	for _, m := range materiales {
		a := models.Auditoria{
			Tipo:    "verificacion_diaria",
			Detalle: fmt.Sprintf("Material %s con stock bajo (%d).", m.Nombre, m.Stock),
		}
		if err := db.WithContext(ctx).Create(&a).Error; err != nil {
			log.Printf("no se pudo guardar auditoría de material bajo: %v", err)
		}
	}
	return nil
}

func checkStaleMissions(ctx context.Context, db *gorm.DB) error {
	limitTime := time.Now().Add(-24 * time.Hour)

	var misiones []models.Mision
	if err := db.WithContext(ctx).
		Where("estado <> ?", "completada").
		Where("updated_at < ?", limitTime).
		Order("id asc").
		Find(&misiones).Error; err != nil {
		return fmt.Errorf("no se pudieron leer misiones viejas: %w", err)
	}

	for _, m := range misiones {
		a := models.Auditoria{
			Tipo:    "verificacion_diaria",
			Detalle: fmt.Sprintf("Misión %d (%s) lleva más de 24h sin completarse.", m.ID, m.Titulo),
		}
		if err := db.WithContext(ctx).Create(&a).Error; err != nil {
			log.Printf("no se pudo guardar auditoría de misión: %v", err)
		}
	}
	return nil
}
