-- Script para crear tabla auxiliar para guardar pagos eliminados por baja de residente
-- Ejecutar este script en la base de datos PostgreSQL

CREATE TABLE IF NOT EXISTS pago_residente_baja (
    id_registro SERIAL PRIMARY KEY,
    id_pago INTEGER NOT NULL,
    id_residente INTEGER NOT NULL,
    id_residencia INTEGER NOT NULL,
    monto DECIMAL(10, 2) NOT NULL,
    fecha_pago DATE NOT NULL,
    fecha_prevista DATE,
    mes_pagado VARCHAR(20),
    concepto TEXT,
    metodo_pago VARCHAR(50),
    estado VARCHAR(50),
    fecha_creacion TIMESTAMP,
    fecha_baja_residente DATE NOT NULL,
    fecha_restauracion TIMESTAMP,
    FOREIGN KEY (id_pago) REFERENCES pago_residente(id_pago) ON DELETE CASCADE,
    FOREIGN KEY (id_residente) REFERENCES residente(id_residente),
    FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia)
);

CREATE INDEX IF NOT EXISTS idx_pago_residente_baja_residente ON pago_residente_baja(id_residente);
CREATE INDEX IF NOT EXISTS idx_pago_residente_baja_pago ON pago_residente_baja(id_pago);

-- Si la tabla ya existe pero no tiene fecha_prevista, añadirla
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pago_residente_baja' 
        AND column_name = 'fecha_prevista'
    ) THEN
        ALTER TABLE pago_residente_baja ADD COLUMN fecha_prevista DATE;
    END IF;
END $$;
