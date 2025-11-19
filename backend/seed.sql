BEGIN;

INSERT INTO alquimistas (id, nombre, email, rango, especialidad, password_hash)
VALUES
    (1, 'Supervisor Demo', 'supervisor@demo.test', 'supervisor', 'Control', '$2a$10$rQqZyrUdg/J3w6RepQiX8.ZLxgMlmqLZUGnGfcG0iIllfy/DAblSW'),
    (2, 'Alquimista Demo', 'alquimista@demo.test', 'alquimista', 'Transmutación', '$2a$10$rQqZyrUdg/J3w6RepQiX8.ZLxgMlmqLZUGnGfcG0iIllfy/DAblSW')
ON CONFLICT (id) DO NOTHING;

INSERT INTO materiales (id, nombre, stock)
VALUES
    (1, 'Mena de hierro', 120),
    (2, 'Fragmento de filosofer', 8),
    (3, 'Catalizador arcano', 35)
ON CONFLICT (id) DO NOTHING;

INSERT INTO misiones (id, titulo, estado, alquimista_id)
VALUES
    (1, 'Vigilar frontera norte', 'en_progreso', 2),
    (2, 'Auditar laboratorio central', 'pendiente', 1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO transmutaciones (id, alquimista_id, material_id, estado, costo, resultado)
VALUES
    (1, 2, 1, 'aprobada', 45.5, 'Placas reforzadas listas para despliegue'),
    (2, 2, 3, 'pendiente', 120.0, NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO auditorias (id, tipo, detalle)
VALUES
    (1, 'auth_login', 'Inicio de sesión de Supervisor Demo'),
    (2, 'transmutacion', 'Transmutación #1 aprobada por el consejo')
ON CONFLICT (id) DO NOTHING;

COMMIT;
