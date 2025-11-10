package models

import "time"

const (
	RoleAlquimista = "alquimista"
	RoleSupervisor = "supervisor"

	EstadoMisionPendiente  = "pendiente"
	EstadoMisionEnProgreso = "en_progreso"
	EstadoMisionCompletada = "completada"

	EstadoTransmutacionPendiente  = "pendiente"
	EstadoTransmutacionProcesando = "procesando"
	EstadoTransmutacionAprobada   = "aprobada"
	EstadoTransmutacionRechazada  = "rechazada"
)

var (
	RangosValidos = map[string]struct{}{
		RoleAlquimista: {},
		RoleSupervisor: {},
	}
	EstadosMisionValidos = map[string]struct{}{
		EstadoMisionPendiente:  {},
		EstadoMisionEnProgreso: {},
		EstadoMisionCompletada: {},
	}
	EstadosTransmutacionValidos = map[string]struct{}{
		EstadoTransmutacionPendiente:  {},
		EstadoTransmutacionProcesando: {},
		EstadoTransmutacionAprobada:   {},
		EstadoTransmutacionRechazada:  {},
	}
)

type Alquimista struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Nombre       string    `gorm:"not null" json:"nombre"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	Rango        string    `gorm:"type:varchar(20);not null" json:"rango"`
	Especialidad string    `json:"especialidad"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Alquimista) TableName() string {
	return "alquimistas"
}

type Mision struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Titulo       string    `gorm:"not null" json:"titulo"`
	Estado       string    `gorm:"type:varchar(20);not null" json:"estado"`
	AlquimistaID uint      `gorm:"not null" json:"alquimista_id"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Mision) TableName() string {
	return "misiones"
}

type Material struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Nombre    string    `gorm:"uniqueIndex;not null" json:"nombre"`
	Stock     int       `gorm:"not null" json:"stock"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Material) TableName() string {
	return "materiales"
}

type Transmutacion struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	AlquimistaID uint      `gorm:"not null" json:"alquimista_id"`
	MaterialID   uint      `gorm:"not null" json:"material_id"`
	Estado       string    `gorm:"type:varchar(20);not null" json:"estado"`
	Costo        float64   `gorm:"not null" json:"costo"`
	Resultado    string    `gorm:"type:text" json:"resultado"`
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Transmutacion) TableName() string {
	return "transmutaciones"
}

type Auditoria struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Tipo      string    `gorm:"not null" json:"tipo"`
	Detalle   string    `gorm:"type:text" json:"detalle"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Auditoria) TableName() string {
	return "auditorias"
}
