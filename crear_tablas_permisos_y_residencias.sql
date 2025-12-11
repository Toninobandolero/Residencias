-- Script para crear tablas de permisos y residencias de usuario
-- Ejecutar este script en la base de datos PostgreSQL

-- Tabla de permisos del sistema
CREATE TABLE IF NOT EXISTS permiso (
    nombre_permiso VARCHAR(255) PRIMARY KEY,
    descripcion TEXT,
    activo BOOLEAN DEFAULT TRUE
);

-- Tabla de relación entre roles y permisos
CREATE TABLE IF NOT EXISTS rol_permiso (
    id_rol INTEGER NOT NULL,
    nombre_permiso VARCHAR(255) NOT NULL,
    PRIMARY KEY (id_rol, nombre_permiso),
    FOREIGN KEY (id_rol) REFERENCES rol(id_rol) ON DELETE CASCADE,
    FOREIGN KEY (nombre_permiso) REFERENCES permiso(nombre_permiso) ON DELETE CASCADE
);

-- Tabla de relación entre usuarios y residencias (permite múltiples residencias por usuario)
CREATE TABLE IF NOT EXISTS usuario_residencia (
    id_usuario INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    PRIMARY KEY (id_usuario, id_residencia),
    FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario) ON DELETE CASCADE,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia) ON DELETE CASCADE
);

-- Tabla de permisos personalizados por usuario (opcional)
CREATE TABLE IF NOT EXISTS usuario_permiso (
    id_usuario INTEGER NOT NULL,
    nombre_permiso VARCHAR(255) NOT NULL,
    PRIMARY KEY (id_usuario, nombre_permiso),
    FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario) ON DELETE CASCADE,
    FOREIGN KEY (nombre_permiso) REFERENCES permiso(nombre_permiso) ON DELETE CASCADE
);

-- Índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_rol_permiso_rol ON rol_permiso(id_rol);
CREATE INDEX IF NOT EXISTS idx_rol_permiso_permiso ON rol_permiso(nombre_permiso);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia_usuario ON usuario_residencia(id_usuario);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia_residencia ON usuario_residencia(id_residencia);
CREATE INDEX IF NOT EXISTS idx_usuario_permiso_usuario ON usuario_permiso(id_usuario);
