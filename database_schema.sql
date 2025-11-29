-- Esquema de base de datos esperado para el sistema Violetas
-- Nota: Según los requisitos, las tablas ya están definidas en PostgreSQL
-- Este archivo documenta la estructura esperada

-- Tabla de residencias (Violetas 1 y Violetas 2)
-- Se espera que exista con al menos:
-- id_residencia: 1 (Violetas 1), 2 (Violetas 2)

-- Tabla de roles
-- Se espera que exista con roles definidos

-- Tabla de usuarios (ESTRUCTURA REQUERIDA PARA EL LOGIN)
CREATE TABLE IF NOT EXISTS usuario (
    id_usuario SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    id_rol INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    -- Campos adicionales opcionales:
    -- nombre VARCHAR(255),
    -- apellido VARCHAR(255),
    -- activo BOOLEAN DEFAULT TRUE,
    -- fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- FOREIGN KEY (id_rol) REFERENCES rol(id_rol),
    -- FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Índices recomendados para mejor rendimiento
CREATE INDEX IF NOT EXISTS idx_usuario_email ON usuario(email);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia ON usuario(id_residencia);

-- Ejemplo de inserción de usuario (usar db_utils.py para hashear contraseñas)
-- INSERT INTO usuario (email, password_hash, id_rol, id_residencia)
-- VALUES (
--     'admin@violetas1.com',
--     'pbkdf2:sha256:600000$...',  -- Usar generate_password_hash de Werkzeug
--     1,  -- ID del rol (ajustar según tu tabla de roles)
--     1   -- ID de residencia (1 = Violetas 1, 2 = Violetas 2)
-- );

