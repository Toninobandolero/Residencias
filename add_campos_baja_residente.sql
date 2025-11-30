-- Script para agregar campos de baja a la tabla residente
-- Motivo de baja y fecha de baja

ALTER TABLE residente 
ADD COLUMN IF NOT EXISTS motivo_baja VARCHAR(100),
ADD COLUMN IF NOT EXISTS fecha_baja DATE;

-- Comentarios para documentación
COMMENT ON COLUMN residente.motivo_baja IS 'Motivo de la baja del residente (fallecimiento, traslado a hospital, traslado a otra residencia, etc.)';
COMMENT ON COLUMN residente.fecha_baja IS 'Fecha en que se dio de baja al residente';

