#!/usr/bin/env python3
"""
Script para verificar y crear permiso escribir:residencia.
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def fix_residencia_permisos():
    """Crea permiso escribir:residencia si no existe."""
    print("=" * 70)
    print("  FIX: Permiso escribir:residencia")
    print("=" * 70)
    print()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Verificar permisos de residencia existentes
        print("📝 Paso 1: Verificando permisos de residencia...")
        cursor.execute("""
            SELECT nombre_permiso, descripcion, activo
            FROM permiso
            WHERE nombre_permiso LIKE '%residencia%'
            ORDER BY nombre_permiso
        """)
        
        permisos_existentes = cursor.fetchall()
        print(f"  ✅ {len(permisos_existentes)} permisos encontrados:")
        for p in permisos_existentes:
            print(f"     • {p[0]:25s} Activo={p[2]}")
        
        # 2. Crear permiso escribir:residencia si no existe
        print()
        print("📝 Paso 2: Creando permiso escribir:residencia...")
        cursor.execute("""
            INSERT INTO permiso (nombre_permiso, descripcion, activo)
            VALUES ('escribir:residencia', 'Permite editar información de residencias', TRUE)
            ON CONFLICT (nombre_permiso) DO UPDATE
            SET descripcion = EXCLUDED.descripcion,
                activo = TRUE
        """)
        conn.commit()
        print("  ✅ escribir:residencia creado/actualizado")
        
        # 3. Obtener ID del rol Administrador
        print()
        print("📝 Paso 3: Obteniendo rol Administrador...")
        cursor.execute("""
            SELECT id_rol, nombre
            FROM rol
            WHERE nombre = 'Administrador'
        """)
        
        rol_admin = cursor.fetchone()
        if not rol_admin:
            print("  ❌ ERROR: Rol Administrador no encontrado")
            return False
        
        id_rol_admin = rol_admin[0]
        print(f"  ✅ Rol Administrador encontrado (ID: {id_rol_admin})")
        
        # 4. Asignar permiso al rol Administrador
        print()
        print("📝 Paso 4: Asignando permiso al rol Administrador...")
        cursor.execute("""
            INSERT INTO rol_permiso (id_rol, nombre_permiso)
            VALUES (%s, 'escribir:residencia')
            ON CONFLICT (id_rol, nombre_permiso) DO NOTHING
        """, (id_rol_admin,))
        conn.commit()
        print(f"  ✅ escribir:residencia → Administrador")
        
        # 5. Verificar permisos de residencia del Administrador
        print()
        print("📝 Paso 5: Verificando permisos de residencia del Administrador...")
        cursor.execute("""
            SELECT rp.nombre_permiso
            FROM rol_permiso rp
            WHERE rp.id_rol = %s AND rp.nombre_permiso LIKE '%%residencia%%'
            ORDER BY rp.nombre_permiso
        """, (id_rol_admin,))
        
        permisos_asignados = cursor.fetchall()
        print(f"  ✅ {len(permisos_asignados)} permisos asignados:")
        for permiso in permisos_asignados:
            print(f"     • {permiso[0]}")
        
        cursor.close()
        conn.close()
        
        print()
        print("=" * 70)
        print("  ✅ PROCESO COMPLETADO EXITOSAMENTE")
        print("=" * 70)
        print()
        print("💡 SIGUIENTE PASO:")
        print("   El servidor ya está reiniciado.")
        print("   Intenta editar una residencia ahora.")
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    fix_residencia_permisos()
