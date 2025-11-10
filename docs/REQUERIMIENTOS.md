# Requerimientos técnicos

## Backend (Go 1.24+)

- Ejecutar con `go run ./cmd/api` desde el contenedor de Docker Compose.
- Variables de entorno claves:
  - `PORT`: puerto HTTP (por defecto `8080`).
  - `JWT_SECRET`: secreto para firmar tokens.
  - `DB_DSN` **o** los componentes `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSLMODE`.
  - `REDIS_URL`: URL de conexión a Redis (por defecto `redis://redis:6379/0`).
- Migraciones automáticas y seed inicial manejados por GORM y `backend/seed.sql`.
- Endpoints expuestos bajo `/api/v1`, con `GET /healthz` para chequeos básicos.

## Frontend (Node 22+ con Vite)

- Ejecutar con `npm run dev -- --host 0.0.0.0 --port 3000` dentro del servicio Docker.
- Variables de entorno consumidas por Vite:
  - `VITE_API_URL`: URL base del backend (por defecto `http://api:8080`).
  - `VITE_API_WS_URL`: endpoint WebSocket (`ws://api:8080`).
- Páginas clave:
  - `Alquimista.tsx`: panel operativo con tabla de transmutaciones y notificaciones en vivo.
  - `Supervisor.tsx`: resumen ejecutivo con uso de materiales y auditorías.

## Infraestructura (Docker Compose v2+)

- Servicios incluidos: `api` (Go), `web` (React), `db` (PostgreSQL 16), `redis` (Redis 7).
- Volúmenes:
  - `postgres-data`: persistencia de PostgreSQL.
- Inicialización de base de datos mediante `backend/seed.sql`.
- No se generan binarios en la imagen: el backend usa `go run` y el frontend `npm run dev`.

## Puesta en marcha

```bash
docker compose up --build
```

Una vez levantados los servicios:

- Backend disponible en `http://localhost:8080` (`/healthz`, `/api/v1/...`).
- Frontend de desarrollo en `http://localhost:3000`.
- PostgreSQL accesible con las credenciales `alquimia/alquimia` en el puerto `5432`.
- Redis disponible en el puerto `6379`.
