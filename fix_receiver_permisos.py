#!/usr/bin/env python3
"""
Script para crear permisos de receiver y asignarlos al rol Administrador.
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def fix_receiver_permisos():
    """Crea permisos de receiver y los asigna al rol Administrador."""
    print("=" * 70)
    print("  FIX: Permisos de Receiver (Entidades Fiscales)")
    print("=" * 70)
    print()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Crear permisos de receiver si no existen
        print("📝 Paso 1: Creando permisos de receiver...")
        permisos_receiver = [
            ("leer:receiver", "Permite leer/listar entidades fiscales (receiver)"),
            ("escribir:receiver", "Permite crear y modificar entidades fiscales (receiver)"),
        ]
        
        for nombre_permiso, descripcion in permisos_receiver:
            cursor.execute("""
                INSERT INTO permiso (nombre_permiso, descripcion, activo)
                VALUES (%s, %s, TRUE)
                ON CONFLICT (nombre_permiso) DO UPDATE
                SET descripcion = EXCLUDED.descripcion,
                    activo = TRUE
            """, (nombre_permiso, descripcion))
            print(f"  ✅ {nombre_permiso}")
        
        conn.commit()
        
        # 2. Obtener ID del rol Administrador
        print()
        print("📝 Paso 2: Obteniendo rol Administrador...")
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
        
        # 3. Asignar permisos al rol Administrador
        print()
        print("📝 Paso 3: Asignando permisos al rol Administrador...")
        for nombre_permiso, _ in permisos_receiver:
            cursor.execute("""
                INSERT INTO rol_permiso (id_rol, nombre_permiso)
                VALUES (%s, %s)
                ON CONFLICT (id_rol, nombre_permiso) DO NOTHING
            """, (id_rol_admin, nombre_permiso))
            print(f"  ✅ {nombre_permiso} → Administrador")
        
        conn.commit()
        
        # 4. Verificar que los permisos existen
        print()
        print("📝 Paso 4: Verificando permisos creados...")
        cursor.execute("""
            SELECT nombre_permiso, descripcion
            FROM permiso
            WHERE nombre_permiso LIKE '%receiver%'
            ORDER BY nombre_permiso
        """)
        
        permisos = cursor.fetchall()
        print(f"  ✅ {len(permisos)} permisos de receiver encontrados:")
        for permiso in permisos:
            print(f"     • {permiso[0]}: {permiso[1]}")
        
        # 5. Verificar asignación al rol
        print()
        print("📝 Paso 5: Verificando asignación a rol Administrador...")
        cursor.execute("""
            SELECT rp.nombre_permiso
            FROM rol_permiso rp
            WHERE rp.id_rol = %s AND rp.nombre_permiso LIKE '%receiver%'
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
        print("   Reinicia el servidor Flask para aplicar los cambios")
        print()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False

if __name__ == '__main__':
    fix_receiver_permisos()
