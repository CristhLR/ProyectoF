package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/proyectof/backend/internal/models"
)

func checkMisiones(ctx context.Context, db *gorm.DB) error {
	cutoff := time.Now().Add(-24 * time.Hour)

	var count int64
	if err := db.WithContext(ctx).Model(&models.Mision{}).
		Where("estado IN ? AND created_at <= ?", []string{models.EstadoMisionPendiente, models.EstadoMisionEnProgreso}, cutoff).
		Count(&count).Error; err != nil {
		return fmt.Errorf("count misiones: %w", err)
	}

	if count == 0 {
		return nil
	}

	detalle := fmt.Sprintf("%d misiones con más de 24h en pendiente o en progreso", count)
	return createAuditIfNeeded(ctx, db, "checks_misiones", detalle)
}

func checkMateriales(ctx context.Context, db *gorm.DB) error {
	var materiales []models.Material
	if err := db.WithContext(ctx).Where("stock < ?", 5).Find(&materiales).Error; err != nil {
		return fmt.Errorf("listar materiales: %w", err)
	}

	if len(materiales) == 0 {
		return nil
	}

	nombres := make([]string, 0, len(materiales))
	for _, material := range materiales {
		nombres = append(nombres, fmt.Sprintf("%s (stock: %d)", material.Nombre, material.Stock))
	}

	detalle := fmt.Sprintf("Materiales con bajo stock: %s", strings.Join(nombres, ", "))
	return createAuditIfNeeded(ctx, db, "checks_materiales", detalle)
}

func checkTransmutaciones(ctx context.Context, db *gorm.DB) error {
	cutoff := time.Now().Add(-6 * time.Hour)

	var count int64
	if err := db.WithContext(ctx).Model(&models.Transmutacion{}).
		Where("estado IN ? AND created_at <= ?", []string{models.EstadoTransmutacionPendiente, models.EstadoTransmutacionProcesando}, cutoff).
		Count(&count).Error; err != nil {
		return fmt.Errorf("count transmutaciones: %w", err)
	}

	if count == 0 {
		return nil
	}

	detalle := fmt.Sprintf("%d transmutaciones pendientes/procesando con más de 6h", count)
	return createAuditIfNeeded(ctx, db, "checks_transmutaciones", detalle)
}

func createAuditIfNeeded(ctx context.Context, db *gorm.DB, tipo, detalle string) error {
	twelveHoursAgo := time.Now().Add(-12 * time.Hour)

	var existing int64
	if err := db.WithContext(ctx).Model(&models.Auditoria{}).
		Where("tipo = ? AND created_at >= ?", tipo, twelveHoursAgo).
		Count(&existing).Error; err != nil {
		return fmt.Errorf("check existing audit for %s: %w", tipo, err)
	}

	if existing > 0 {
		return nil
	}

	audit := models.Auditoria{
		Tipo:    tipo,
		Detalle: detalle,
	}

	if err := db.WithContext(ctx).Create(&audit).Error; err != nil {
		return fmt.Errorf("create audit %s: %w", tipo, err)
	}

	log.Printf("audit created: %s", detalle)
	return nil
}
