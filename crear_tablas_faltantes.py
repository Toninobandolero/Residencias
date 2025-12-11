#!/usr/bin/env python3
"""
Script para crear las tablas faltantes: usuario_residencia, permiso, rol_permiso, usuario_permiso
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def crear_tablas():
    """Crea las tablas faltantes para el sistema de permisos y residencias."""
    print("=" * 60)
    print("  CREANDO TABLAS FALTANTES")
    print("=" * 60)
    print()
    
    sql = """
    -- Tabla de permisos del sistema
    CREATE TABLE IF NOT EXISTS permiso (
        nombre_permiso VARCHAR(255) PRIMARY KEY,
        descripcion TEXT,
        activo BOOLEAN DEFAULT TRUE
    );

    -- Tabla de relación entre roles y permisos
    CREATE TABLE IF NOT EXISTS rol_permiso (
        id_rol INTEGER NOT NULL,
        nombre_permiso VARCHAR(255) NOT NULL,
        PRIMARY KEY (id_rol, nombre_permiso),
        FOREIGN KEY (id_rol) REFERENCES rol(id_rol) ON DELETE CASCADE,
        FOREIGN KEY (nombre_permiso) REFERENCES permiso(nombre_permiso) ON DELETE CASCADE
    );

    -- Tabla de relación entre usuarios y residencias
    CREATE TABLE IF NOT EXISTS usuario_residencia (
        id_usuario INTEGER NOT NULL,
        id_residencia INTEGER NOT NULL,
        PRIMARY KEY (id_usuario, id_residencia),
        FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario) ON DELETE CASCADE,
        FOREIGN KEY (id_residencia) REFERENCES residencia(id_residencia) ON DELETE CASCADE
    );

    -- Tabla de permisos personalizados por usuario
    CREATE TABLE IF NOT EXISTS usuario_permiso (
        id_usuario INTEGER NOT NULL,
        nombre_permiso VARCHAR(255) NOT NULL,
        PRIMARY KEY (id_usuario, nombre_permiso),
        FOREIGN KEY (id_usuario) REFERENCES usuario(id_usuario) ON DELETE CASCADE,
        FOREIGN KEY (nombre_permiso) REFERENCES permiso(nombre_permiso) ON DELETE CASCADE
    );

    -- Índices
    CREATE INDEX IF NOT EXISTS idx_rol_permiso_rol ON rol_permiso(id_rol);
    CREATE INDEX IF NOT EXISTS idx_rol_permiso_permiso ON rol_permiso(nombre_permiso);
    CREATE INDEX IF NOT EXISTS idx_usuario_residencia_usuario ON usuario_residencia(id_usuario);
    CREATE INDEX IF NOT EXISTS idx_usuario_residencia_residencia ON usuario_residencia(id_residencia);
    CREATE INDEX IF NOT EXISTS idx_usuario_permiso_usuario ON usuario_permiso(id_usuario);
    """
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        print("Creando tablas...")
        cursor.execute(sql)
        conn.commit()
        
        print("✅ Tablas creadas exitosamente:")
        print("   - permiso")
        print("   - rol_permiso")
        print("   - usuario_residencia")
        print("   - usuario_permiso")
        print()
        
        # Verificar que se crearon
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('permiso', 'rol_permiso', 'usuario_residencia', 'usuario_permiso')
            ORDER BY table_name
        """)
        tablas = cursor.fetchall()
        
        print("Tablas verificadas:")
        for tabla in tablas:
            print(f"   ✅ {tabla[0]}")
        
        cursor.close()
        conn.close()
        
        print()
        print("=" * 60)
        print("  ✅ PROCESO COMPLETADO")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    crear_tablas()
