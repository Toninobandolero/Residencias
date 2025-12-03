"""
Script para verificar y crear los roles necesarios.
"""
from db_connector import get_db_connection

def verificar_y_crear_roles():
    """
    Verifica qué roles existen y crea los que faltan.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("\n" + "="*70)
        print("VERIFICACIÓN Y CREACIÓN DE ROLES")
        print("="*70 + "\n")
        
        # Verificar roles existentes
        cursor.execute("SELECT id_rol, nombre, descripcion, activo FROM rol ORDER BY id_rol")
        roles_existentes = cursor.fetchall()
        
        print("Roles existentes en la base de datos:")
        for rol in roles_existentes:
            print(f"  - ID: {rol[0]}, Nombre: {rol[1]}, Activo: {rol[3]}")
        
        # Definir roles necesarios
        roles_necesarios = [
            (1, 'super_admin', 'Super Administrador con acceso total', True),
            (2, 'Administrador', 'Administrador con acceso a todos los módulos y permisos de todas las residencias', True),
            (3, 'Director', 'Director de residencia con gestión completa', True),
            (4, 'Personal', 'Personal de la residencia con permisos limitados', True)
        ]
        
        print("\nVerificando y creando roles necesarios...")
        
        for id_rol, nombre, descripcion, activo in roles_necesarios:
            cursor.execute("SELECT id_rol, nombre FROM rol WHERE id_rol = %s", (id_rol,))
            rol_existente = cursor.fetchone()
            
            if rol_existente:
                # Actualizar si el nombre es diferente
                if rol_existente[1] != nombre:
                    print(f"  ⚠️  Actualizando rol ID {id_rol}: '{rol_existente[1]}' -> '{nombre}'")
                    cursor.execute("""
                        UPDATE rol 
                        SET nombre = %s, descripcion = %s, activo = %s
                        WHERE id_rol = %s
                    """, (nombre, descripcion, activo, id_rol))
                    conn.commit()
                    print(f"  ✅ Rol {id_rol} actualizado: {nombre}")
                else:
                    print(f"  ✅ Rol {id_rol} ya existe: {nombre}")
            else:
                # Crear el rol
                print(f"  ➕ Creando rol {id_rol}: {nombre}")
                cursor.execute("""
                    INSERT INTO rol (id_rol, nombre, descripcion, activo)
                    VALUES (%s, %s, %s, %s)
                """, (id_rol, nombre, descripcion, activo))
                conn.commit()
                print(f"  ✅ Rol {id_rol} creado: {nombre}")
        
        # Verificar roles finales
        print("\n" + "="*70)
        print("ROLES FINALES")
        print("="*70)
        cursor.execute("SELECT id_rol, nombre, descripcion, activo FROM rol ORDER BY id_rol")
        roles_finales = cursor.fetchall()
        for rol in roles_finales:
            print(f"  ID {rol[0]}: {rol[1]} - {rol[2]}")
        
        print("\n" + "="*70 + "\n")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    verificar_y_crear_roles()

