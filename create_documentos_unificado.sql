-- Tabla unificada para almacenar documentación de todas las entidades
-- Soporta: residentes, proveedores, personal
CREATE TABLE IF NOT EXISTS documento (
    id_documento SERIAL PRIMARY KEY,
    tipo_entidad VARCHAR(50) NOT NULL,  -- 'residente', 'proveedor', 'personal'
    id_entidad INTEGER NOT NULL,  -- ID de la entidad (id_residente, id_proveedor, id_personal)
    id_residencia INTEGER NOT NULL,
    categoria_documento VARCHAR(100) NOT NULL,  -- 'medica', 'fiscal', 'sanitaria', 'laboral', 'otra'
    tipo_documento VARCHAR(100) NOT NULL,  -- Tipo específico (ej: 'DNI', 'Informe médico', 'Factura')
    nombre_archivo VARCHAR(255) NOT NULL,
    descripcion TEXT,
    fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    url_archivo VARCHAR(500),
    tamaño_bytes BIGINT,
    tipo_mime VARCHAR(100),
    id_usuario_subida INTEGER,  -- Usuario que subió el documento
    activo BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia),
    FOREIGN KEY (id_usuario_subida) REFERENCES usuario(id_usuario)
);

-- Índices para mejorar el rendimiento
CREATE INDEX IF NOT EXISTS idx_documento_tipo_entidad ON documento(tipo_entidad);
CREATE INDEX IF NOT EXISTS idx_documento_id_entidad ON documento(id_entidad);
CREATE INDEX IF NOT EXISTS idx_documento_residencia ON documento(id_residencia);
CREATE INDEX IF NOT EXISTS idx_documento_categoria ON documento(categoria_documento);
CREATE INDEX IF NOT EXISTS idx_documento_tipo_documento ON documento(tipo_documento);
CREATE INDEX IF NOT EXISTS idx_documento_activo ON documento(activo);

-- Índice compuesto para búsquedas frecuentes
CREATE INDEX IF NOT EXISTS idx_documento_entidad_residencia ON documento(tipo_entidad, id_entidad, id_residencia);

