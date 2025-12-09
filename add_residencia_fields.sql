-- Script para añadir nuevos campos a la tabla residencia
-- Ejecutar este script en la base de datos PostgreSQL

ALTER TABLE residencia 
ADD COLUMN IF NOT EXISTS nombre_fiscal VARCHAR(255),
ADD COLUMN IF NOT EXISTS nif VARCHAR(20),
ADD COLUMN IF NOT EXISTS codigo_postal VARCHAR(10),
ADD COLUMN IF NOT EXISTS ciudad VARCHAR(100),
ADD COLUMN IF NOT EXISTS provincia VARCHAR(100),
ADD COLUMN IF NOT EXISTS email VARCHAR(255),
ADD COLUMN IF NOT EXISTS web VARCHAR(255),
ADD COLUMN IF NOT EXISTS cuenta_bancaria VARCHAR(34),
ADD COLUMN IF NOT EXISTS observaciones TEXT;

