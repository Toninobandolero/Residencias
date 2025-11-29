-- Tabla para almacenar documentación de residentes
CREATE TABLE IF NOT EXISTS documento_residente (
    id_documento SERIAL PRIMARY KEY,
    id_residente INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    tipo_documento VARCHAR(100) NOT NULL,
    nombre_archivo VARCHAR(255) NOT NULL,
    descripcion TEXT,
    fecha_subida TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residente) REFERENCES residente(id_residente) ON DELETE CASCADE,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

-- Índices para mejorar el rendimiento
CREATE INDEX IF NOT EXISTS idx_documento_residente_residente ON documento_residente(id_residente);
CREATE INDEX IF NOT EXISTS idx_documento_residente_residencia ON documento_residente(id_residencia);
CREATE INDEX IF NOT EXISTS idx_documento_residente_tipo ON documento_residente(tipo_documento);

