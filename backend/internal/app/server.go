package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/proyectof/backend/internal/models"
)

type contextKey string

const (
	contextKeyUserID contextKey = "user_id"
	contextKeyRole   contextKey = "role"
)

const (
	redisQueueKey        = "queue:transmutaciones"
	redisNotificationsCh = "notifications:transmutaciones"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		// si en el futuro agregas otra URL frontend, la pones aquí
		return origin == "" || origin == "http://localhost:3000"
	},
}

type Server struct {
	db          *gorm.DB
	jwtSecret   []byte
	redisClient *redis.Client

	wsMu      sync.Mutex
	wsClients map[*websocket.Conn]struct{}
}

func NewServer(db *gorm.DB, jwtSecret []byte, redisClient *redis.Client) *Server {
	server := &Server{
		db:          db,
		jwtSecret:   jwtSecret,
		redisClient: redisClient,
		wsClients:   make(map[*websocket.Conn]struct{}),
	}

	// si hay redis, escuchamos las notificaciones para mandarlas por websocket
	if redisClient != nil {
		go server.listenForNotifications()
	}

	return server
}

func (s *Server) Router() http.Handler {
	router := mux.NewRouter()
	router.Use(mux.CORSMethodMiddleware(router))

	// salud
	router.HandleFunc("/healthz", s.handleHealth).Methods(http.MethodGet)

	// websocket
	router.HandleFunc("/api/v1/ws/notificaciones", s.handleNotificationsWS).Methods(http.MethodGet)

	// prefijo API
	api := router.PathPrefix("/api/v1").Subrouter()

	// auth pública
	api.HandleFunc("/auth/register", s.handleRegister).Methods(http.MethodPost)
	api.HandleFunc("/auth/login", s.handleLogin).Methods(http.MethodPost)

	// preflight
	api.PathPrefix("/").Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	secured := api.PathPrefix("").Subrouter()
	secured.Use(s.authMiddleware)

	//alquimistas
	secured.HandleFunc("/alquimistas", s.handleListAlquimistas).Methods(http.MethodGet)
	secured.HandleFunc("/alquimistas", s.handleCreateAlquimista).Methods(http.MethodPost)
	secured.HandleFunc("/alquimistas/{id}", s.handleUpdateAlquimista).Methods(http.MethodPut)
	secured.HandleFunc("/alquimistas/{id}", s.handleDeleteAlquimista).Methods(http.MethodDelete)
	secured.HandleFunc("/alquimistas/me", s.handleGetCurrentAlquimista).Methods(http.MethodGet)

	//misiones
	secured.HandleFunc("/misiones", s.handleListMisiones).Methods(http.MethodGet)
	secured.HandleFunc("/misiones", s.handleCreateMision).Methods(http.MethodPost)
	secured.HandleFunc("/misiones/{id}", s.handleUpdateMision).Methods(http.MethodPut)
	secured.HandleFunc("/misiones/{id}", s.handleDeleteMision).Methods(http.MethodDelete)

	//materiales
	secured.HandleFunc("/materiales", s.handleListMateriales).Methods(http.MethodGet)
	secured.HandleFunc("/materiales", s.handleCreateMaterial).Methods(http.MethodPost)
	secured.HandleFunc("/materiales/{id}", s.handleUpdateMaterial).Methods(http.MethodPut)
	secured.HandleFunc("/materiales/{id}", s.handleDeleteMaterial).Methods(http.MethodDelete)

	//transmutaciones
	secured.HandleFunc("/transmutaciones", s.handleListTransmutaciones).Methods(http.MethodGet)
	secured.HandleFunc("/transmutaciones", s.handleCreateTransmutacion).Methods(http.MethodPost)
	secured.HandleFunc("/transmutaciones/{id}", s.handleUpdateTransmutacion).Methods(http.MethodPut)
	secured.HandleFunc("/transmutaciones/{id}", s.handleDeleteTransmutacion).Methods(http.MethodDelete)
	secured.HandleFunc("/transmutaciones/{id}/procesar", s.handleProcessTransmutacion).Methods(http.MethodPost)
	secured.HandleFunc("/transmutaciones/{id}/aprobar", s.handleApproveTransmutacion).Methods(http.MethodPost)
	secured.HandleFunc("/transmutaciones/{id}/rechazar", s.handleRejectTransmutacion).Methods(http.MethodPost)

	//auditorías para el supervisor (CRUD completo)
	secured.HandleFunc("/auditorias", s.handleListAuditorias).Methods(http.MethodGet)
	secured.HandleFunc("/auditorias", s.handleCreateAuditoria).Methods(http.MethodPost)
	secured.HandleFunc("/auditorias/{id}", s.handleUpdateAuditoria).Methods(http.MethodPut)
	secured.HandleFunc("/auditorias/{id}", s.handleDeleteAuditoria).Methods(http.MethodDelete)

	//CORS
	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{"http://localhost:3000"}),
		handlers.AllowedMethods([]string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		}),
		handlers.AllowedHeaders([]string{"Authorization", "Content-Type"}),
		handlers.AllowCredentials(),
	)

	return cors(router)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type registerRequest struct {
	Nombre       string `json:"nombre"`
	Email        string `json:"email"`
	Especialidad string `json:"especialidad"`
	Password     string `json:"password"`
	Rango        string `json:"rango"`
}

type authResponse struct {
	Token string            `json:"token"`
	User  models.Alquimista `json:"user"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Nombre == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "nombre, email y password son obligatorios")
		return
	}

	rango := req.Rango
	if rango == "" {
		rango = models.RoleAlquimista
	}

	if _, ok := models.RangosValidos[rango]; !ok {
		writeError(w, http.StatusBadRequest, "rango inválido")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo generar el password hash")
		return
	}

	alquimista := models.Alquimista{
		Nombre:       req.Nombre,
		Email:        strings.ToLower(req.Email),
		Especialidad: req.Especialidad,
		PasswordHash: string(hash),
		Rango:        rango,
	}

	if err := s.db.Create(&alquimista).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusBadRequest, "el email ya está registrado")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo registrar al usuario")
		return
	}

	s.recordAudit(r.Context(), "auth_register", fmt.Sprintf("Nuevo registro de %s", alquimista.Email))

	token, err := s.generateToken(alquimista.ID, alquimista.Rango)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo generar el token")
		return
	}

	writeJSON(w, http.StatusCreated, authResponse{Token: token, User: sanitizeAlquimista(alquimista)})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var alquimista models.Alquimista
	if err := s.db.Where("email = ?", strings.ToLower(req.Email)).First(&alquimista).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusUnauthorized, "credenciales inválidas")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo iniciar sesión")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(alquimista.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "credenciales inválidas")
		return
	}

	token, err := s.generateToken(alquimista.ID, alquimista.Rango)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo generar el token")
		return
	}

	s.recordAudit(r.Context(), "auth_login", fmt.Sprintf("Ingreso de %s", alquimista.Email))

	writeJSON(w, http.StatusOK, authResponse{Token: token, User: sanitizeAlquimista(alquimista)})
}

func (s *Server) generateToken(userID uint, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "token requerido")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("método de firma inválido")
			}
			return s.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}

		userIDFloat, ok := claims["user_id"].(float64)
		if !ok {
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}

		role, ok := claims["role"].(string)
		if !ok {
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}

		ctx := context.WithValue(r.Context(), contextKeyUserID, uint(userIDFloat))
		ctx = context.WithValue(ctx, contextKeyRole, role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireSupervisor(r *http.Request) bool {
	role, _ := r.Context().Value(contextKeyRole).(string)
	return role == models.RoleSupervisor
}

func (s *Server) currentUserID(r *http.Request) (uint, bool) {
	userID, ok := r.Context().Value(contextKeyUserID).(uint)
	return userID, ok
}

func sanitizeAlquimista(alq models.Alquimista) models.Alquimista {
	alq.PasswordHash = ""
	return alq
}

func (s *Server) handleListAlquimistas(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	var alquimistas []models.Alquimista
	if err := s.db.Order("id asc").Find(&alquimistas).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudieron obtener los alquimistas")
		return
	}

	for i := range alquimistas {
		alquimistas[i] = sanitizeAlquimista(alquimistas[i])
	}

	writeJSON(w, http.StatusOK, alquimistas)
}

func (s *Server) handleCreateAlquimista(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Nombre == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "nombre, email y password son obligatorios")
		return
	}

	if req.Rango == "" {
		req.Rango = models.RoleAlquimista
	}

	if _, ok := models.RangosValidos[req.Rango]; !ok {
		writeError(w, http.StatusBadRequest, "rango inválido")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo generar el password hash")
		return
	}

	alquimista := models.Alquimista{
		Nombre:       req.Nombre,
		Email:        strings.ToLower(req.Email),
		Especialidad: req.Especialidad,
		PasswordHash: string(hash),
		Rango:        req.Rango,
	}

	if err := s.db.Create(&alquimista).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusBadRequest, "el email ya está registrado")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo crear el alquimista")
		return
	}

	s.recordAudit(r.Context(), "alquimistas_create", fmt.Sprintf("Creación de %s", alquimista.Email))

	writeJSON(w, http.StatusCreated, sanitizeAlquimista(alquimista))
}

func (s *Server) handleUpdateAlquimista(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var alquimista models.Alquimista
	if err := s.db.First(&alquimista, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "alquimista no encontrado")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el alquimista")
		return
	}

	if req.Nombre != "" {
		alquimista.Nombre = req.Nombre
	}
	if req.Especialidad != "" {
		alquimista.Especialidad = req.Especialidad
	}
	if req.Rango != "" {
		if _, ok := models.RangosValidos[req.Rango]; !ok {
			writeError(w, http.StatusBadRequest, "rango inválido")
			return
		}
		alquimista.Rango = req.Rango
	}
	if req.Email != "" {
		alquimista.Email = strings.ToLower(req.Email)
	}
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "no se pudo actualizar el password")
			return
		}
		alquimista.PasswordHash = string(hash)
	}

	if err := s.db.Save(&alquimista).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar el alquimista")
		return
	}

	s.recordAudit(r.Context(), "alquimistas_update", fmt.Sprintf("Actualización de %s", alquimista.Email))

	writeJSON(w, http.StatusOK, sanitizeAlquimista(alquimista))
}

func (s *Server) handleDeleteAlquimista(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	if err := s.db.Delete(&models.Alquimista{}, id).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo eliminar el alquimista")
		return
	}

	s.recordAudit(r.Context(), "alquimistas_delete", fmt.Sprintf("Eliminación de alquimista %d", id))

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetCurrentAlquimista(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.currentUserID(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el usuario actual")
		return
	}

	var alquimista models.Alquimista
	if err := s.db.First(&alquimista, userID).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el usuario actual")
		return
	}

	writeJSON(w, http.StatusOK, sanitizeAlquimista(alquimista))
}

type misionRequest struct {
	Titulo       string `json:"titulo"`
	Estado       string `json:"estado"`
	AlquimistaID uint   `json:"alquimista_id"`
}

func (s *Server) handleListMisiones(w http.ResponseWriter, r *http.Request) {
	var misiones []models.Mision
	if err := s.db.Order("id asc").Find(&misiones).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudieron obtener las misiones")
		return
	}

	writeJSON(w, http.StatusOK, misiones)
}

func (s *Server) handleCreateMision(w http.ResponseWriter, r *http.Request) {
	var req misionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Titulo == "" {
		writeError(w, http.StatusBadRequest, "titulo requerido")
		return
	}

	if req.Estado == "" {
		req.Estado = models.EstadoMisionPendiente
	}

	if _, ok := models.EstadosMisionValidos[req.Estado]; !ok {
		writeError(w, http.StatusBadRequest, "estado inválido")
		return
	}

	mision := models.Mision{
		Titulo:       req.Titulo,
		Estado:       req.Estado,
		AlquimistaID: req.AlquimistaID,
	}

	if err := s.db.Create(&mision).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo crear la misión")
		return
	}

	s.recordAudit(r.Context(), "misiones_create", fmt.Sprintf("Misión %s creada", mision.Titulo))

	writeJSON(w, http.StatusCreated, mision)
}

func (s *Server) handleUpdateMision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var req misionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var mision models.Mision
	if err := s.db.First(&mision, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "misión no encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener la misión")
		return
	}

	if req.Titulo != "" {
		mision.Titulo = req.Titulo
	}
	if req.Estado != "" {
		if _, ok := models.EstadosMisionValidos[req.Estado]; !ok {
			writeError(w, http.StatusBadRequest, "estado inválido")
			return
		}
		mision.Estado = req.Estado
	}
	if req.AlquimistaID != 0 {
		mision.AlquimistaID = req.AlquimistaID
	}

	if err := s.db.Save(&mision).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar la misión")
		return
	}

	s.recordAudit(r.Context(), "misiones_update", fmt.Sprintf("Misión %d actualizada", mision.ID))

	writeJSON(w, http.StatusOK, mision)
}

func (s *Server) handleDeleteMision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	if err := s.db.Delete(&models.Mision{}, id).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo eliminar la misión")
		return
	}

	s.recordAudit(r.Context(), "misiones_delete", fmt.Sprintf("Misión %d eliminada", id))

	w.WriteHeader(http.StatusNoContent)
}

type materialRequest struct {
	Nombre string `json:"nombre"`
	Stock  *int   `json:"stock"`
}

func (s *Server) handleListMateriales(w http.ResponseWriter, r *http.Request) {
	var materiales []models.Material
	if err := s.db.Order("id asc").Find(&materiales).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudieron obtener los materiales")
		return
	}

	writeJSON(w, http.StatusOK, materiales)
}

func (s *Server) handleCreateMaterial(w http.ResponseWriter, r *http.Request) {
	var req materialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.Nombre == "" || req.Stock == nil {
		writeError(w, http.StatusBadRequest, "nombre y stock son obligatorios")
		return
	}

	material := models.Material{
		Nombre: req.Nombre,
		Stock:  *req.Stock,
	}

	if err := s.db.Create(&material).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusBadRequest, "el material ya existe")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo crear el material")
		return
	}

	s.recordAudit(r.Context(), "materiales_create", fmt.Sprintf("Material %s creado", material.Nombre))

	writeJSON(w, http.StatusCreated, material)
}

func (s *Server) handleUpdateMaterial(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var req materialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var material models.Material
	if err := s.db.First(&material, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "material no encontrado")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el material")
		return
	}

	if req.Nombre != "" {
		material.Nombre = req.Nombre
	}
	if req.Stock != nil {
		material.Stock = *req.Stock
	}

	if err := s.db.Save(&material).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar el material")
		return
	}

	s.recordAudit(r.Context(), "materiales_update", fmt.Sprintf("Material %d actualizado", material.ID))

	writeJSON(w, http.StatusOK, material)
}

func (s *Server) handleDeleteMaterial(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	if err := s.db.Delete(&models.Material{}, id).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo eliminar el material")
		return
	}

	s.recordAudit(r.Context(), "materiales_delete", fmt.Sprintf("Material %d eliminado", id))

	w.WriteHeader(http.StatusNoContent)
}

type transmutacionRequest struct {
	AlquimistaID uint     `json:"alquimista_id"`
	MaterialID   uint     `json:"material_id"`
	Estado       string   `json:"estado"`
	Costo        *float64 `json:"costo"`
	Resultado    string   `json:"resultado"`
}

func (s *Server) handleListTransmutaciones(w http.ResponseWriter, r *http.Request) {
	var transmutaciones []models.Transmutacion
	if err := s.db.Order("id asc").Find(&transmutaciones).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudieron obtener las transmutaciones")
		return
	}

	writeJSON(w, http.StatusOK, transmutaciones)
}

func (s *Server) handleCreateTransmutacion(w http.ResponseWriter, r *http.Request) {
	var req transmutacionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if req.AlquimistaID == 0 || req.MaterialID == 0 || req.Costo == nil {
		writeError(w, http.StatusBadRequest, "alquimista_id, material_id y costo son obligatorios")
		return
	}

	if *req.Costo < 0 {
		writeError(w, http.StatusBadRequest, "el costo no puede ser negativo")
		return
	}

	if req.Estado == "" {
		req.Estado = models.EstadoTransmutacionPendiente
	}
	if _, ok := models.EstadosTransmutacionValidos[req.Estado]; !ok {
		writeError(w, http.StatusBadRequest, "estado inválido")
		return
	}

	var transmutacion models.Transmutacion

	txErr := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		//traer material
		var material models.Material
		if err := tx.First(&material, req.MaterialID).Error; err != nil {
			return fmt.Errorf("material no encontrado")
		}

		//cuánto stock vamos a consumir
		consumo := int(math.Ceil(*req.Costo))
		if consumo < 1 {
			consumo = 1
		}

		if material.Stock < consumo {
			return fmt.Errorf(
				"no hay stock suficiente para este material (disponible: %d, requerido: %d)",
				material.Stock,
				consumo,
			)
		}

		resultado := strings.TrimSpace(req.Resultado)
		if resultado == "" {
			switch material.Nombre {
			case "Lingote de hierro":
				resultado = "Lingote de hierro reforzado para uso militar"
			case "Piedra filosofal sintética":
				resultado = "Catalizador de alta pureza"
			case "Sellos de tiza reforzada":
				resultado = "Círculo de contención mejorado"
			default:
				resultado = "Transmutación básica completada"
			}
		}

		//descontar stock según el costo
		material.Stock = material.Stock - consumo
		if err := tx.Save(&material).Error; err != nil {
			return err
		}

		//crear la transmutación
		t := models.Transmutacion{
			AlquimistaID: req.AlquimistaID,
			MaterialID:   req.MaterialID,
			Estado:       req.Estado,
			Costo:        *req.Costo,
			Resultado:    resultado,
		}
		if err := tx.Create(&t).Error; err != nil {
			return err
		}

		transmutacion = t
		return nil
	})

	if txErr != nil {
		if strings.Contains(txErr.Error(), "material no encontrado") || strings.Contains(txErr.Error(), "no hay stock suficiente") {
			writeError(w, http.StatusBadRequest, txErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo crear la transmutación")
		return
	}

	s.recordAudit(r.Context(), "transmutaciones_create", fmt.Sprintf("Transmutación %d creada", transmutacion.ID))

	writeJSON(w, http.StatusCreated, transmutacion)
}

func (s *Server) handleUpdateTransmutacion(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var req transmutacionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var transmutacion models.Transmutacion
	if err := s.db.First(&transmutacion, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "transmutación no encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener la transmutación")
		return
	}

	if req.AlquimistaID != 0 {
		transmutacion.AlquimistaID = req.AlquimistaID
	}
	if req.MaterialID != 0 {
		transmutacion.MaterialID = req.MaterialID
	}
	if req.Estado != "" {
		if _, ok := models.EstadosTransmutacionValidos[req.Estado]; !ok {
			writeError(w, http.StatusBadRequest, "estado inválido")
			return
		}
		transmutacion.Estado = req.Estado
	}
	if req.Costo != nil {
		transmutacion.Costo = *req.Costo
	}
	if req.Resultado != "" {
		transmutacion.Resultado = req.Resultado
	}

	if err := s.db.Save(&transmutacion).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar la transmutación")
		return
	}

	s.recordAudit(r.Context(), "transmutaciones_update", fmt.Sprintf("Transmutación %d actualizada", transmutacion.ID))

	writeJSON(w, http.StatusOK, transmutacion)
}

func (s *Server) handleDeleteTransmutacion(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	if err := s.db.Delete(&models.Transmutacion{}, id).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo eliminar la transmutación")
		return
	}

	s.recordAudit(r.Context(), "transmutaciones_delete", fmt.Sprintf("Transmutación %d eliminada", id))

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleProcessTransmutacion(w http.ResponseWriter, r *http.Request) {
	if s.redisClient == nil {
		writeError(w, http.StatusInternalServerError, "redis no configurado")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var transmutacion models.Transmutacion
	if err := s.db.WithContext(r.Context()).First(&transmutacion, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "transmutación no encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener la transmutación")
		return
	}

	if transmutacion.Estado == models.EstadoTransmutacionAprobada {
		writeError(w, http.StatusBadRequest, "la transmutación ya está aprobada")
		return
	}

	if transmutacion.Estado != models.EstadoTransmutacionProcesando {
		transmutacion.Estado = models.EstadoTransmutacionProcesando
		if err := s.db.WithContext(r.Context()).Save(&transmutacion).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "no se pudo actualizar la transmutación")
			return
		}
	}

	if err := s.redisClient.RPush(r.Context(), redisQueueKey, transmutacion.ID).Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo encolar la transmutación")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "en cola"})
}

// ====== AQUÍ VA LA VERSIÓN CORREGIDA SIN DESCUENTO DE STOCK ======
func (s *Server) handleApproveTransmutacion(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	supervisorID, ok := s.currentUserID(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el supervisor")
		return
	}

	txErr := s.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		var supervisor models.Alquimista
		if err := tx.First(&supervisor, supervisorID).Error; err != nil {
			return err
		}

		var transmutacion models.Transmutacion
		if err := tx.First(&transmutacion, id).Error; err != nil {
			return err
		}

		if transmutacion.Estado == models.EstadoTransmutacionAprobada {
			return fmt.Errorf("la transmutación ya está aprobada")
		}

		transmutacion.Estado = models.EstadoTransmutacionAprobada
		if err := tx.Save(&transmutacion).Error; err != nil {
			return err
		}

		audit := models.Auditoria{
			Tipo:    "transmutaciones_manual",
			Detalle: fmt.Sprintf("Transmutación %d aprobada por %s.", transmutacion.ID, supervisor.Nombre),
		}
		_ = tx.Create(&audit).Error

		return nil
	})

	if txErr != nil {
		if strings.Contains(txErr.Error(), "ya está aprobada") {
			writeError(w, http.StatusBadRequest, txErr.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo aprobar la transmutación")
		return
	}

	if s.redisClient != nil {
		if err := s.redisClient.Publish(r.Context(), redisNotificationsCh, fmt.Sprintf("%d", id)).Err(); err != nil {
			log.Printf("redis publish error: %v", err)
		}
	}

	var updated models.Transmutacion
	if err := s.db.WithContext(r.Context()).First(&updated, id).Error; err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "aprobado"})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ===================================================

func (s *Server) handleRejectTransmutacion(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var supervisor models.Alquimista
	supervisorID, ok := s.currentUserID(r)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el supervisor")
		return
	}

	if err := s.db.WithContext(r.Context()).First(&supervisor, supervisorID).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo obtener el supervisor")
		return
	}

	var transmutacion models.Transmutacion
	if err := s.db.WithContext(r.Context()).First(&transmutacion, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "transmutación no encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener la transmutación")
		return
	}

	if transmutacion.Estado == models.EstadoTransmutacionRechazada {
		writeError(w, http.StatusBadRequest, "la transmutación ya está rechazada")
		return
	}
	if transmutacion.Estado == models.EstadoTransmutacionAprobada {
		writeError(w, http.StatusBadRequest, "la transmutación ya está aprobada")
		return
	}

	transmutacion.Estado = models.EstadoTransmutacionRechazada
	if err := s.db.WithContext(r.Context()).Save(&transmutacion).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar la transmutación")
		return
	}

	s.recordAudit(r.Context(), "transmutaciones_manual", fmt.Sprintf("Transmutación %d rechazada por supervisor %s", transmutacion.ID, supervisor.Nombre))

	writeJSON(w, http.StatusOK, transmutacion)
}

func (s *Server) handleNotificationsWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade error: %v", err)
		return
	}

	s.wsMu.Lock()
	s.wsClients[conn] = struct{}{}
	s.wsMu.Unlock()

	go func() {
		defer func() {
			s.wsMu.Lock()
			delete(s.wsClients, conn)
			s.wsMu.Unlock()
			_ = conn.Close()
		}()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

func (s *Server) listenForNotifications() {
	ctx := context.Background()
	for {
		if s.redisClient == nil {
			return
		}

		pubsub := s.redisClient.Subscribe(ctx, redisNotificationsCh)
		for {
			msg, err := pubsub.ReceiveMessage(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					_ = pubsub.Close()
					return
				}
				log.Printf("redis subscription error: %v", err)
				break
			}
			s.broadcastNotification(fmt.Sprintf("Transmutacion %s aprobada", msg.Payload))
		}
		_ = pubsub.Close()
		time.Sleep(2 * time.Second)
	}
}

func (s *Server) broadcastNotification(message string) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	for conn := range s.wsClients {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			log.Printf("websocket send error: %v", err)
			_ = conn.Close()
			delete(s.wsClients, conn)
		}
	}
}

type auditoriaRequest struct {
	Tipo    string `json:"tipo"`
	Detalle string `json:"detalle"`
}

func (s *Server) handleListAuditorias(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	var auditorias []models.Auditoria
	if err := s.db.Order("id DESC").Limit(200).Find(&auditorias).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudieron obtener las auditorías")
		return
	}

	writeJSON(w, http.StatusOK, auditorias)
}

func (s *Server) handleCreateAuditoria(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	var req auditoriaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	tipo := strings.TrimSpace(req.Tipo)
	detalle := strings.TrimSpace(req.Detalle)

	if tipo == "" {
		writeError(w, http.StatusBadRequest, "tipo es obligatorio")
		return
	}

	audit := models.Auditoria{
		Tipo:    tipo,
		Detalle: detalle,
	}

	if err := s.db.Create(&audit).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo crear la auditoría")
		return
	}

	s.recordAudit(r.Context(), "auditorias_create_manual", fmt.Sprintf("Auditoría %d creada manualmente", audit.ID))

	writeJSON(w, http.StatusCreated, audit)
}

func (s *Server) handleUpdateAuditoria(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	var req auditoriaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var audit models.Auditoria
	if err := s.db.First(&audit, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "auditoría no encontrada")
			return
		}
		writeError(w, http.StatusInternalServerError, "no se pudo obtener la auditoría")
		return
	}

	tipo := strings.TrimSpace(req.Tipo)
	detalle := strings.TrimSpace(req.Detalle)

	if tipo != "" {
		audit.Tipo = tipo
	}
	if detalle != "" {
		audit.Detalle = detalle
	}

	if err := s.db.Save(&audit).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo actualizar la auditoría")
		return
	}

	s.recordAudit(r.Context(), "auditorias_update_manual", fmt.Sprintf("Auditoría %d actualizada manualmente", audit.ID))

	writeJSON(w, http.StatusOK, audit)
}

func (s *Server) handleDeleteAuditoria(w http.ResponseWriter, r *http.Request) {
	if !s.requireSupervisor(r) {
		writeError(w, http.StatusForbidden, "solo supervisores")
		return
	}

	id, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "id inválido")
		return
	}

	if err := s.db.Delete(&models.Auditoria{}, id).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "no se pudo eliminar la auditoría")
		return
	}

	s.recordAudit(r.Context(), "auditorias_delete_manual", fmt.Sprintf("Auditoría %d eliminada manualmente", id))

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) recordAudit(ctx context.Context, tipo, detalle string) {
	if tipo == "" {
		return
	}

	audit := models.Auditoria{
		Tipo:    tipo,
		Detalle: detalle,
	}
	if err := s.db.WithContext(ctx).Create(&audit).Error; err != nil {
		fmt.Printf("error saving audit: %v\n", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
