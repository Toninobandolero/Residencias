-- Script para agregar campos adicionales a la tabla residente
-- Coste de habitación, servicios extra, medicaciones y peculiaridades

ALTER TABLE residente 
ADD COLUMN IF NOT EXISTS costo_habitacion DECIMAL(10, 2),
ADD COLUMN IF NOT EXISTS servicios_extra TEXT,
ADD COLUMN IF NOT EXISTS medicaciones TEXT,
ADD COLUMN IF NOT EXISTS peculiaridades TEXT;

