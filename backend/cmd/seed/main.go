package main

import (
	"errors"
	"log"
	"strings"

	"github.com/proyectof/backend/internal/config"
	"github.com/proyectof/backend/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func main() {
	db, err := config.InitDatabase()
	if err != nil {
		log.Fatal(err)
	}

	// 1) asegurar que existan los usuarios base 
	supervisor, err := ensureUser(db, models.Alquimista{
		Nombre:       "Supervisor Demo",
		Email:        "supervisor@demo.test",
		Rango:        models.RoleSupervisor,
		Especialidad: "Control",
	}, "demo123")
	if err != nil {
		log.Fatal(err)
	}

	alquimista, err := ensureUser(db, models.Alquimista{
		Nombre:       "Alquimista Demo",
		Email:        "alquimista@demo.test",
		Rango:        models.RoleAlquimista,
		Especialidad: "Transmutación",
	}, "demo123")
	if err != nil {
		log.Fatal(err)
	}

	// 2) materiales de ejemplo
	materialSpecs := []struct {
		Nombre string
		Stock  int
	}{
		{"Lingote de hierro", 30},
		{"Piedra filosofal sintética", 10},
		{"Sellos de tiza reforzada", 25},
		{"Metal Automail", 20},
		{"Cristal de Energía", 15},
	}

	materiales := make(map[string]models.Material)
	for _, spec := range materialSpecs {
		var mat models.Material
		err := db.Where("nombre = ?", spec.Nombre).
			Attrs(models.Material{Stock: spec.Stock}).
			FirstOrCreate(&mat).Error
		if err != nil {
			log.Fatal(err)
		}
		materiales[spec.Nombre] = mat
	}

	// 3) misiones de ejemplo para el alquimista demo
	misiones := []struct {
		Titulo string
		Estado string
	}{
		{"Recolectar fragmentos de energon", models.EstadoMisionPendiente},
		{"Inspeccionar puertas de la verdad", models.EstadoMisionEnProgreso},
		{"Refinar catalizadores alquímicos", models.EstadoMisionCompletada},
	}

	for _, m := range misiones {
		var mm models.Mision
		err := db.Where(models.Mision{
			Titulo:       m.Titulo,
			AlquimistaID: alquimista.ID,
		}).Attrs(models.Mision{
			Estado: m.Estado,
		}).FirstOrCreate(&mm).Error
		if err != nil {
			log.Fatal(err)
		}
	}

	// 4) transmutaciones de ejemplo
	transmutSpecs := []struct {
		MaterialNombre string
		Estado         string
		Costo          float64
		Resultado      string
	}{
		{
			MaterialNombre: "Piedra filosofal sintética",
			Estado:         models.EstadoTransmutacionPendiente,
			Costo:          1200,
			Resultado:      "Reacción inicial estabilizada",
		},
		{
			MaterialNombre: "Lingote de hierro",
			Estado:         models.EstadoTransmutacionProcesando,
			Costo:          75,
			Resultado:      "Lingote de hierro reforzado para uso militar",
		},
		{
			MaterialNombre: "Cristal de Energía",
			Estado:         models.EstadoTransmutacionAprobada,
			Costo:          460,
			Resultado:      "Cristal cargado y aprobado",
		},
	}

	for _, t := range transmutSpecs {
		mat, ok := materiales[t.MaterialNombre]
		if !ok {
			log.Fatalf("material %s no encontrado para seed de transmutaciones", t.MaterialNombre)
		}

		var tr models.Transmutacion
		err := db.Where(models.Transmutacion{
			AlquimistaID: alquimista.ID,
			MaterialID:   mat.ID,
			Resultado:    t.Resultado,
		}).Attrs(models.Transmutacion{
			Estado: t.Estado,
			Costo:  t.Costo,
		}).FirstOrCreate(&tr).Error
		if err != nil {
			log.Fatal(err)
		}
	}

	// 5) auditorías base
	audits := []models.Auditoria{
		{Tipo: "sistema", Detalle: "Sincronización inicial del panel completada"},
		{Tipo: "actividad", Detalle: "El alquimista demo revisó las transmutaciones"},
		{Tipo: "seguridad", Detalle: "El supervisor demo inició sesión para revisar transmutaciones"},
	}
	for _, a := range audits {
		var au models.Auditoria
		err := db.Where("tipo = ? AND detalle = ?", a.Tipo, a.Detalle).
			FirstOrCreate(&au, a).Error
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("seed aplicado correctamente ✅")
	log.Printf("usuario supervisor: %s / %s\n", supervisor.Email, "demo123")
	log.Printf("usuario alquimista: %s / %s\n", alquimista.Email, "demo123")
}

// ensureUser busca por email y si no existe lo crea con la contraseña indicada.
func ensureUser(db *gorm.DB, base models.Alquimista, plainPassword string) (models.Alquimista, error) {
	base.Email = strings.ToLower(base.Email)

	var existing models.Alquimista
	err := db.Where("email = ?", base.Email).First(&existing).Error
	if err == nil {
		// ya existe
		return existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return models.Alquimista{}, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return models.Alquimista{}, err
	}

	base.PasswordHash = string(hash)
	if base.Rango == "" {
		base.Rango = models.RoleAlquimista
	}

	if err := db.Create(&base).Error; err != nil {
		return models.Alquimista{}, err
	}

	return base, nil
}
