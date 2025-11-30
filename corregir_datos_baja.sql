-- Script para corregir los datos intercambiados en motivo_baja y fecha_baja
-- Este script intercambia los valores de motivo_baja y fecha_baja para los residentes inactivos

-- Primero, crear una tabla temporal para guardar los datos actuales
CREATE TEMP TABLE temp_baja_data AS
SELECT 
    id_residente,
    motivo_baja,
    fecha_baja
FROM residente
WHERE activo = FALSE 
  AND (motivo_baja IS NOT NULL OR fecha_baja IS NOT NULL);

-- Verificar los datos antes de corregir
SELECT 
    id_residente,
    motivo_baja as motivo_actual,
    fecha_baja as fecha_actual,
    CASE 
        WHEN fecha_baja ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN 'fecha_baja parece ser una fecha'
        WHEN fecha_baja IS NOT NULL AND fecha_baja !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN 'fecha_baja parece ser un motivo'
        ELSE 'fecha_baja está vacío'
    END as diagnostico_fecha,
    CASE 
        WHEN motivo_baja ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN 'motivo_baja parece ser una fecha'
        WHEN motivo_baja IS NOT NULL AND motivo_baja !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN 'motivo_baja parece ser un motivo'
        ELSE 'motivo_baja está vacío'
    END as diagnostico_motivo
FROM temp_baja_data;

-- Intercambiar los valores donde fecha_baja contiene texto (motivo) y motivo_baja está vacío o contiene fecha
UPDATE residente
SET 
    motivo_baja = fecha_baja,
    fecha_baja = motivo_baja
WHERE activo = FALSE
  AND fecha_baja IS NOT NULL 
  AND fecha_baja !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'  -- fecha_baja contiene texto (no es una fecha)
  AND (motivo_baja IS NULL OR motivo_baja ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}');  -- motivo_baja está vacío o es una fecha

-- Verificar los datos después de corregir
SELECT 
    id_residente,
    motivo_baja as motivo_corregido,
    fecha_baja as fecha_corregida
FROM residente
WHERE activo = FALSE 
  AND (motivo_baja IS NOT NULL OR fecha_baja IS NOT NULL)
ORDER BY id_residente;

