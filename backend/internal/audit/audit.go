package audit

import (
    "context"
    "time"
    "gorm.io/gorm"
)

type Auditoria struct {
    ID        int64     `gorm:"primaryKey"`
    ActorID   *int64    
    Accion    string    `gorm:"not null"`
    Entidad   string    `gorm:"not null"`
    EntidadID *int64
    Detalle   string
    CreatedAt time.Time `gorm:"autoCreateTime"`
}

func Registrar(ctx context.Context, db *gorm.DB, a Auditoria) {
    _ = db.WithContext(ctx).Create(&a).Error
}
