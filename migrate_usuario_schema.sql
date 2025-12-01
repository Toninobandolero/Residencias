-- Script de migración para actualizar esquema de usuario
-- Ejecutar antes de iniciar el servidor con el nuevo sistema

-- 1. Agregar campo requiere_cambio_clave a tabla usuario
ALTER TABLE usuario 
ADD COLUMN IF NOT EXISTS requiere_cambio_clave BOOLEAN DEFAULT TRUE;

-- 2. Actualizar usuarios existentes para que requieran cambio de clave
UPDATE usuario SET requiere_cambio_clave = TRUE WHERE requiere_cambio_clave IS NULL;

-- 3. Eliminar columna id_residencia de usuario (ahora se usa usuario_residencia)
-- NOTA: Primero asegúrate de migrar los datos a usuario_residencia si existen usuarios
-- ALTER TABLE usuario DROP COLUMN IF EXISTS id_residencia;

-- NOTA IMPORTANTE: 
-- Antes de eliminar id_residencia, asegúrate de:
-- 1. Migrar todos los registros de usuario.id_residencia a usuario_residencia
-- 2. Verificar que no haya dependencias
-- 3. Hacer backup de la base de datos

-- Script para migrar datos existentes (ejecutar ANTES de eliminar la columna):
-- INSERT INTO usuario_residencia (id_usuario, id_residencia)
-- SELECT id_usuario, id_residencia FROM usuario WHERE id_residencia IS NOT NULL
-- ON CONFLICT DO NOTHING;

