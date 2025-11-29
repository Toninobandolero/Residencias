-- Script para agregar el campo habitacion a la tabla residente
-- Ejecutar este script si la tabla ya existe

ALTER TABLE residente 
ADD COLUMN IF NOT EXISTS habitacion VARCHAR(50);

-- Crear índice para búsquedas por habitación
CREATE INDEX IF NOT EXISTS idx_residente_habitacion ON residente(habitacion);

