package config

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/proyectof/backend/internal/models"
)

func InitDatabase() (*gorm.DB, error) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		return nil, errors.New("DB_DSN environment variable is required")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	if err := db.AutoMigrate(
		&models.Alquimista{},
		&models.Mision{},
		&models.Material{},
		&models.Transmutacion{},
		&models.Auditoria{},
	); err != nil {
		return nil, fmt.Errorf("auto migrate: %w", err)
	}

	if err := seedDefaultUsers(db); err != nil {
		return nil, fmt.Errorf("seed users: %w", err)
	}

	return db, nil
}

func seedDefaultUsers(db *gorm.DB) error {
	defaultUsers := []struct {
		email        string
		nombre       string
		rango        string
		especialidad string
	}{
		{
			email:        "supervisor@demo.test",
			nombre:       "Supervisor Demo",
			rango:        models.RoleSupervisor,
			especialidad: "Control",
		},
		{
			email:        "alquimista@demo.test",
			nombre:       "Alquimista Demo",
			rango:        models.RoleAlquimista,
			especialidad: "Transmutación",
		},
	}

	for _, user := range defaultUsers {
		var existing models.Alquimista
		err := db.Where("email = ?", user.email).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			hash, hashErr := bcrypt.GenerateFromPassword([]byte("demo123"), bcrypt.DefaultCost)
			if hashErr != nil {
				return fmt.Errorf("hash password: %w", hashErr)
			}

			alquimista := models.Alquimista{
				Nombre:       user.nombre,
				Email:        user.email,
				Rango:        user.rango,
				Especialidad: user.especialidad,
				PasswordHash: string(hash),
			}
			if err := db.Create(&alquimista).Error; err != nil {
				return fmt.Errorf("create default user: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("find user: %w", err)
		}
	}

	return nil
}
