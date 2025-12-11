-- Esquema de base de datos para el sistema de gestión de residencias Violetas
-- Crea todas las tablas necesarias para el MVP

-- Tabla de residencias (Violetas 1 y Violetas 2)
CREATE TABLE IF NOT EXISTS residencia (
    id_residencia SERIAL PRIMARY KEY,
    nombre VARCHAR(255) NOT NULL,
    direccion VARCHAR(500),
    telefono VARCHAR(50),
    activa BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de roles
CREATE TABLE IF NOT EXISTS rol (
    id_rol SERIAL PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL UNIQUE,
    descripcion TEXT,
    activo BOOLEAN DEFAULT TRUE
);

-- Tabla de usuarios (CRÍTICA para el login)
CREATE TABLE IF NOT EXISTS usuario (
    id_usuario SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    id_rol INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    nombre VARCHAR(255),
    apellido VARCHAR(255),
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_rol) REFERENCES rol(id_rol),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de residentes
CREATE TABLE IF NOT EXISTS residente (
    id_residente SERIAL PRIMARY KEY,
    id_residencia INTEGER NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    apellido VARCHAR(255) NOT NULL,
    documento_identidad VARCHAR(50),
    fecha_nacimiento DATE,
    telefono VARCHAR(50),
    direccion TEXT,
    contacto_emergencia VARCHAR(255),
    telefono_emergencia VARCHAR(50),
    activo BOOLEAN DEFAULT TRUE,
    fecha_ingreso DATE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de personal
CREATE TABLE IF NOT EXISTS personal (
    id_personal SERIAL PRIMARY KEY,
    id_residencia INTEGER NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    apellido VARCHAR(255) NOT NULL,
    documento_identidad VARCHAR(50),
    telefono VARCHAR(50),
    email VARCHAR(255),
    cargo VARCHAR(100),
    activo BOOLEAN DEFAULT TRUE,
    fecha_contratacion DATE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de pagos de residentes
CREATE TABLE IF NOT EXISTS pago_residente (
    id_pago SERIAL PRIMARY KEY,
    id_residente INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    monto DECIMAL(10, 2) NOT NULL,
    fecha_pago DATE NOT NULL,
    mes_pagado VARCHAR(20),
    concepto TEXT,
    metodo_pago VARCHAR(50),
    estado VARCHAR(50) DEFAULT 'pendiente',
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residente) REFERENCES residente(id_residente),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de pagos a proveedores
CREATE TABLE IF NOT EXISTS pago_proveedor (
    id_pago SERIAL PRIMARY KEY,
    id_residencia INTEGER NOT NULL,
    proveedor VARCHAR(255) NOT NULL,
    concepto TEXT NOT NULL,
    monto DECIMAL(10, 2) NOT NULL,
    fecha_pago DATE NOT NULL,
    metodo_pago VARCHAR(50),
    estado VARCHAR(50) DEFAULT 'pendiente',
    numero_factura VARCHAR(100),
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de turnos normales
CREATE TABLE IF NOT EXISTS turno_normal (
    id_turno SERIAL PRIMARY KEY,
    id_personal INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    fecha DATE NOT NULL,
    hora_entrada TIME NOT NULL,
    hora_salida TIME NOT NULL,
    tipo_turno VARCHAR(50),
    observaciones TEXT,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_personal) REFERENCES personal(id_personal),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de turnos extra
CREATE TABLE IF NOT EXISTS turno_extra (
    id_turno_extra SERIAL PRIMARY KEY,
    id_personal INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    fecha DATE NOT NULL,
    hora_entrada TIME NOT NULL,
    hora_salida TIME NOT NULL,
    motivo TEXT,
    aprobado BOOLEAN DEFAULT FALSE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_personal) REFERENCES personal(id_personal),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Tabla de registros asistenciales
CREATE TABLE IF NOT EXISTS registro_asistencial (
    id_registro SERIAL PRIMARY KEY,
    id_residente INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    tipo_registro VARCHAR(100) NOT NULL,
    descripcion TEXT NOT NULL,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_incidente DATE,
    hora_incidente TIME,
    id_usuario_registro INTEGER,
    observaciones TEXT,
    FOREIGN KEY (id_residente) REFERENCES residente(id_residente),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia),
    FOREIGN KEY (id_usuario_registro) REFERENCES usuario(id_usuario)
);

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

-- Índices para mejorar el rendimiento
CREATE INDEX IF NOT EXISTS idx_usuario_email ON usuario(email);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia ON usuario(id_residencia);
CREATE INDEX IF NOT EXISTS idx_residente_residencia ON residente(id_residencia);
CREATE INDEX IF NOT EXISTS idx_personal_residencia ON personal(id_residencia);
CREATE INDEX IF NOT EXISTS idx_pago_residente_residencia ON pago_residente(id_residencia);
CREATE INDEX IF NOT EXISTS idx_pago_proveedor_residencia ON pago_proveedor(id_residencia);
CREATE INDEX IF NOT EXISTS idx_turno_normal_residencia ON turno_normal(id_residencia);
CREATE INDEX IF NOT EXISTS idx_turno_extra_residencia ON turno_extra(id_residencia);
CREATE INDEX IF NOT EXISTS idx_registro_asistencial_residencia ON registro_asistencial(id_residencia);
CREATE INDEX IF NOT EXISTS idx_rol_permiso_rol ON rol_permiso(id_rol);
CREATE INDEX IF NOT EXISTS idx_rol_permiso_permiso ON rol_permiso(nombre_permiso);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia_usuario ON usuario_residencia(id_usuario);
CREATE INDEX IF NOT EXISTS idx_usuario_residencia_residencia ON usuario_residencia(id_residencia);
CREATE INDEX IF NOT EXISTS idx_usuario_permiso_usuario ON usuario_permiso(id_usuario);

-- Datos iniciales: Residencias
INSERT INTO residencia (id_residencia, nombre) VALUES 
    (1, 'Violetas 1'),
    (2, 'Violetas 2')
ON CONFLICT DO NOTHING;

-- Datos iniciales: Roles básicos
INSERT INTO rol (id_rol, nombre, descripcion) VALUES 
    (1, 'Administrador', 'Acceso completo al sistema'),
    (2, 'Director', 'Gestión de la residencia'),
    (3, 'Personal', 'Personal de la residencia')
ON CONFLICT DO NOTHING;

-- NOTA: Los permisos se inicializan ejecutando: python3 inicializar_permisos.py
-- Esto asegura que todos los permisos necesarios estén disponibles antes de crear usuarios

