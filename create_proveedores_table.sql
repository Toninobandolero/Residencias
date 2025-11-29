-- Crear tabla de proveedores
CREATE TABLE IF NOT EXISTS proveedor (
    id_proveedor SERIAL PRIMARY KEY,
    id_residencia INTEGER NOT NULL,
    nombre VARCHAR(255) NOT NULL,
    nif_cif VARCHAR(50),
    direccion TEXT,
    telefono VARCHAR(50),
    email VARCHAR(255),
    contacto VARCHAR(255),
    tipo_servicio VARCHAR(100), -- Ej: Limpieza, Mantenimiento, Alimentación, etc.
    activo BOOLEAN DEFAULT TRUE,
    observaciones TEXT,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

CREATE INDEX IF NOT EXISTS idx_proveedor_residencia ON proveedor(id_residencia);
CREATE INDEX IF NOT EXISTS idx_proveedor_activo ON proveedor(activo);

