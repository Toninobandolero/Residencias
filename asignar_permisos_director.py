#!/usr/bin/env python3
"""
Script para asignar todos los permisos (excepto Configuración) al rol Director (id_rol=3).
"""
import os
from dotenv import load_dotenv

if os.path.exists('.env'):
    load_dotenv()

from db_connector import get_db_connection

def asignar_permisos_director():
    """
    Asigna todos los permisos al Director (id_rol=3) excepto los de Configuración.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("\n" + "="*70)
        print("ASIGNANDO PERMISOS AL DIRECTOR (id_rol=3)")
        print("="*70 + "\n")
        
        id_rol_director = 3
        
        # Verificar que el rol Director existe
        cursor.execute("SELECT id_rol, nombre FROM rol WHERE id_rol = %s", (id_rol_director,))
        rol = cursor.fetchone()
        
        if not rol:
            print(f"❌ Error: El rol con id_rol={id_rol_director} no existe")
            return False
        
        print(f"✅ Rol encontrado: ID={rol[0]}, Nombre={rol[1]}\n")
        
        # Obtener todos los permisos disponibles (excepto Configuración)
        # Permisos de Configuración: leer:usuario, crear:usuario, editar:usuario, eliminar:usuario, leer:residencia, editar:residencia
        cursor.execute("""
            SELECT nombre_permiso 
            FROM permiso 
            WHERE activo = TRUE
              AND nombre_permiso NOT IN (
                  'leer:usuario', 'crear:usuario', 'editar:usuario', 'eliminar:usuario',
                  'leer:residencia', 'editar:residencia'
              )
            ORDER BY nombre_permiso
        """)
        
        permisos_disponibles = [p[0] for p in cursor.fetchall()]
        
        if not permisos_disponibles:
            print("❌ No se encontraron permisos disponibles")
            return False
        
        print(f"Permisos disponibles para asignar: {len(permisos_disponibles)}\n")
        
        # Verificar permisos ya asignados
        cursor.execute("""
            SELECT nombre_permiso 
            FROM rol_permiso 
            WHERE id_rol = %s
        """, (id_rol_director,))
        
        permisos_asignados = set([p[0] for p in cursor.fetchall()])
        
        # Filtrar permisos que ya están asignados
        permisos_a_asignar = [p for p in permisos_disponibles if p not in permisos_asignados]
        
        if permisos_asignados:
            print(f"Permisos ya asignados: {len(permisos_asignados)}")
            for p in sorted(permisos_asignados):
                print(f"  ✓ {p}")
            print()
        
        if not permisos_a_asignar:
            print("✅ Todos los permisos ya están asignados al Director")
            return True
        
        print(f"Asignando {len(permisos_a_asignar)} permisos nuevos...\n")
        
        asignados = 0
        errores = 0
        
        for permiso in permisos_a_asignar:
            try:
                cursor.execute("""
                    INSERT INTO rol_permiso (id_rol, nombre_permiso)
                    VALUES (%s, %s)
                    ON CONFLICT (id_rol, nombre_permiso) DO NOTHING
                """, (id_rol_director, permiso))
                
                if cursor.rowcount > 0:
                    print(f"  ✅ {permiso}")
                    asignados += 1
                else:
                    print(f"  ⚠️  {permiso} (ya existía)")
            except Exception as e:
                print(f"  ❌ {permiso}: {str(e)}")
                errores += 1
        
        conn.commit()
        
        print("\n" + "="*70)
        print("  ✅ PROCESO COMPLETADO")
        print("="*70)
        print(f"Permisos asignados: {asignados}")
        if errores > 0:
            print(f"Errores: {errores}")
        print()
        
        # Mostrar resumen final
        cursor.execute("""
            SELECT COUNT(*) 
            FROM rol_permiso 
            WHERE id_rol = %s
        """, (id_rol_director,))
        
        total_permisos = cursor.fetchone()[0]
        print(f"Total de permisos del Director: {total_permisos}")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        conn.rollback()
        cursor.close()
        conn.close()
        return False

if __name__ == '__main__':
    asignar_permisos_director()
