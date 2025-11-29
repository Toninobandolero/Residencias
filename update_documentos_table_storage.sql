-- Agregar campos para almacenamiento en Cloud Storage
ALTER TABLE documento_residente 
ADD COLUMN IF NOT EXISTS url_archivo VARCHAR(500),
ADD COLUMN IF NOT EXISTS tamaño_bytes BIGINT,
ADD COLUMN IF NOT EXISTS tipo_mime VARCHAR(100);

