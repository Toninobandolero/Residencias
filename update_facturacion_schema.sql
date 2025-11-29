-- Actualizar esquema para Facturación
-- Cobros previstos de residentes y pagos a proveedores con estimaciones

-- Actualizar tabla pago_residente para cobros previstos
ALTER TABLE pago_residente 
ADD COLUMN IF NOT EXISTS fecha_prevista DATE,
ADD COLUMN IF NOT EXISTS es_cobro_previsto BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS observaciones TEXT;

-- Actualizar tabla pago_proveedor para estimaciones
ALTER TABLE pago_proveedor 
ADD COLUMN IF NOT EXISTS fecha_prevista DATE,
ADD COLUMN IF NOT EXISTS es_estimacion BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS frecuencia_pago VARCHAR(50), -- mensual, trimestral, anual, etc.
ADD COLUMN IF NOT EXISTS monto_estimado DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS observaciones TEXT;

-- Crear tabla para historial de pagos a proveedores (para calcular estimaciones)
CREATE TABLE IF NOT EXISTS historial_pago_proveedor (
    id_historial SERIAL PRIMARY KEY,
    id_proveedor INTEGER,
    id_residencia INTEGER NOT NULL,
    monto DECIMAL(10, 2) NOT NULL,
    fecha_pago DATE NOT NULL,
    concepto TEXT,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

CREATE INDEX IF NOT EXISTS idx_historial_proveedor ON historial_pago_proveedor(id_proveedor, id_residencia);

