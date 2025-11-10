package main

import (
	"log"

	"github.com/proyectof/backend/internal/config"
	"github.com/proyectof/backend/internal/models"
	"gorm.io/gorm"
)

func main() {
	var (
		db  *gorm.DB
		err error
	)

	db, err = config.InitDatabase()
	if err != nil {
		log.Fatal(err)
	}

	materialData := []struct {
		Nombre string
		Stock  int
	}{
		{Nombre: "Piedra Filosofal Sintética", Stock: 5},
		{Nombre: "Metal Automail", Stock: 20},
		{Nombre: "Cristal de Energía", Stock: 15},
	}

	materiales := make(map[string]models.Material)
	for _, data := range materialData {
		var material models.Material
		if err := db.Where("nombre = ?", data.Nombre).
			Attrs(models.Material{Stock: data.Stock}).
			FirstOrCreate(&material).Error; err != nil {
			log.Fatal(err)
		}
		materiales[data.Nombre] = material
	}

	var alquimista models.Alquimista
	if err := db.Where("email = ?", "alquimista@demo.test").First(&alquimista).Error; err != nil {
		log.Fatal(err)
	}

	misiones := []struct {
		Titulo string
		Estado string
	}{
		{Titulo: "Recolectar fragmentos de energon", Estado: models.EstadoMisionPendiente},
		{Titulo: "Inspeccionar puertas de la verdad", Estado: models.EstadoMisionEnProgreso},
		{Titulo: "Refinar catalizadores alquímicos", Estado: models.EstadoMisionCompletada},
	}

	for _, data := range misiones {
		var mision models.Mision
		if err := db.Where(models.Mision{Titulo: data.Titulo, AlquimistaID: alquimista.ID}).
			Attrs(models.Mision{Estado: data.Estado}).
			FirstOrCreate(&mision).Error; err != nil {
			log.Fatal(err)
		}
	}

	transmutaciones := []struct {
		MaterialNombre string
		Estado         string
		Costo          float64
		Resultado      string
	}{
		{
			MaterialNombre: "Piedra Filosofal Sintética",
			Estado:         models.EstadoTransmutacionPendiente,
			Costo:          1200,
			Resultado:      "Reacción inicial estabilizada",
		},
		{
			MaterialNombre: "Metal Automail",
			Estado:         models.EstadoTransmutacionProcesando,
			Costo:          850,
			Resultado:      "Aleación reforzada en proceso",
		},
		{
			MaterialNombre: "Cristal de Energía",
			Estado:         models.EstadoTransmutacionAprobada,
			Costo:          460,
			Resultado:      "Cristal cargado y aprobado",
		},
	}

	for _, data := range transmutaciones {
		material, ok := materiales[data.MaterialNombre]
		if !ok {
			log.Fatalf("material %s no encontrado", data.MaterialNombre)
		}

		var transmutacion models.Transmutacion
		if err := db.Where(models.Transmutacion{
			AlquimistaID: alquimista.ID,
			MaterialID:   material.ID,
			Resultado:    data.Resultado,
		}).
			Attrs(models.Transmutacion{Estado: data.Estado, Costo: data.Costo}).
			FirstOrCreate(&transmutacion).Error; err != nil {
			log.Fatal(err)
		}
	}

	auditorias := []models.Auditoria{
		{
			Tipo:    "sistema",
			Detalle: "Sincronización inicial del panel completada",
		},
		{
			Tipo:    "actividad",
			Detalle: "El alquimista demo revisó las transmutaciones",
		},
	}

	for _, data := range auditorias {
		var auditoria models.Auditoria
		if err := db.Where("tipo = ? AND detalle = ?", data.Tipo, data.Detalle).
			FirstOrCreate(&auditoria, data).Error; err != nil {
			log.Fatal(err)
		}
	}

	log.Println("seed aplicado correctamente")
}
