-- Script para limpiar TODOS los datos de la base de datos
-- ADVERTENCIA: Este script eliminará TODOS los registros de todas las tablas
-- Mantendrá la estructura de las tablas pero eliminará todos los datos

BEGIN;

-- Eliminar datos en orden inverso de dependencias (de más específico a más general)

-- 1. Documentos de residentes
DELETE FROM documento_residente;
ALTER SEQUENCE IF EXISTS documento_residente_id_documento_seq RESTART WITH 1;

-- 2. Pagos de residentes (cobros)
DELETE FROM pago_residente;
ALTER SEQUENCE IF EXISTS pago_residente_id_pago_seq RESTART WITH 1;

-- 3. Pagos a proveedores
DELETE FROM pago_proveedor;
ALTER SEQUENCE IF EXISTS pago_proveedor_id_pago_seq RESTART WITH 1;

-- 4. Proveedores
DELETE FROM proveedor;
ALTER SEQUENCE IF EXISTS proveedor_id_proveedor_seq RESTART WITH 1;

-- 5. Residentes
DELETE FROM residente;
ALTER SEQUENCE IF EXISTS residente_id_residente_seq RESTART WITH 1;

-- 6. Usuarios - NO SE ELIMINAN (se preservan todos los usuarios, incluyendo administradores)
-- DELETE FROM usuario WHERE id_rol != 1 OR email NOT LIKE '%admin%';
-- ALTER SEQUENCE IF EXISTS usuario_id_usuario_seq RESTART WITH 1;

-- 7. Residencias (opcional - descomentar si quieres eliminar también las residencias)
-- DELETE FROM residencia;
-- ALTER SEQUENCE IF EXISTS residencia_id_residencia_seq RESTART WITH 1;

-- 8. Roles (opcional - descomentar si quieres eliminar también los roles)
-- DELETE FROM rol WHERE id_rol > 1;  -- Mantener el rol de administrador
-- ALTER SEQUENCE IF EXISTS rol_id_rol_seq RESTART WITH 1;

COMMIT;

-- Verificar estado de las tablas
-- Nota: usuario y residencia deben tener registros (se preservan)
SELECT 
    'documento_residente' as tabla, COUNT(*) as registros FROM documento_residente
UNION ALL
SELECT 'pago_residente', COUNT(*) FROM pago_residente
UNION ALL
SELECT 'pago_proveedor', COUNT(*) FROM pago_proveedor
UNION ALL
SELECT 'proveedor', COUNT(*) FROM proveedor
UNION ALL
SELECT 'residente', COUNT(*) FROM residente
UNION ALL
SELECT 'usuario', COUNT(*) FROM usuario
UNION ALL
SELECT 'residencia', COUNT(*) FROM residencia
ORDER BY tabla;

