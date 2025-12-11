#!/usr/bin/env python3
"""
Script para convertir el usuario actual en Administrador.
Uso: python hacer_administrador.py [email]
Si no se proporciona email, actualizará el primer usuario encontrado.
"""

import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor

# Cargar variables de entorno
load_dotenv()

def get_db_connection():
    """Obtiene una conexión a la base de datos."""
    db_host = os.getenv('DB_HOST')
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    
    if not all([db_host, db_name, db_user, db_password]):
        raise ValueError("Faltan variables de entorno requeridas: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD")
    
    return psycopg2.connect(
        host=db_host,
        port=db_port,
        database=db_name,
        user=db_user,
        password=db_password
    )

def hacer_administrador(email=None):
    """Convierte un usuario en Administrador (id_rol=2)."""
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Buscar usuario
        if email:
            cursor.execute("""
                SELECT id_usuario, email, nombre, apellido, id_rol
                FROM usuario
                WHERE email = %s
            """, (email,))
        else:
            # Si no se proporciona email, obtener el primer usuario
            cursor.execute("""
                SELECT id_usuario, email, nombre, apellido, id_rol
                FROM usuario
                ORDER BY id_usuario
                LIMIT 1
            """)
        
        usuario = cursor.fetchone()
        
        if not usuario:
            print(f"❌ Usuario no encontrado{' con email: ' + email if email else ''}")
            return False
        
        print(f"📋 Usuario encontrado:")
        print(f"   ID: {usuario['id_usuario']}")
        print(f"   Email: {usuario['email']}")
        print(f"   Nombre: {usuario['nombre']} {usuario['apellido']}")
        print(f"   Rol actual: {usuario['id_rol']}")
        
        # Verificar que el rol Administrador existe
        cursor.execute("""
            SELECT id_rol, nombre FROM rol WHERE id_rol = 2
        """)
        rol_admin = cursor.fetchone()
        
        if not rol_admin:
            print("⚠️  El rol Administrador (id_rol=2) no existe. Creándolo...")
            cursor.execute("""
                INSERT INTO rol (id_rol, nombre, descripcion, activo)
                VALUES (2, 'Administrador', 'Administrador con acceso a todos los módulos y permisos de todas las residencias', TRUE)
            """)
            conn.commit()
            print("✅ Rol Administrador creado")
        else:
            print(f"✅ Rol Administrador existe: {rol_admin['nombre']}")
        
        # Actualizar usuario a Administrador
        cursor.execute("""
            UPDATE usuario
            SET id_rol = 2
            WHERE id_usuario = %s
            RETURNING id_usuario, email, id_rol
        """, (usuario['id_usuario'],))
        
        usuario_actualizado = cursor.fetchone()
        conn.commit()
        
        print(f"\n✅ Usuario actualizado exitosamente:")
        print(f"   ID: {usuario_actualizado['id_usuario']}")
        print(f"   Email: {usuario_actualizado['email']}")
        print(f"   Nuevo rol: Administrador (id_rol=2)")
        print(f"\n⚠️  IMPORTANTE: Debes cerrar sesión y volver a iniciar sesión para que los cambios surtan efecto.")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Error al actualizar usuario: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    email = sys.argv[1] if len(sys.argv) > 1 else None
    
    if email:
        print(f"🔍 Buscando usuario con email: {email}")
    else:
        print("🔍 Buscando primer usuario en la base de datos...")
    
    print()
    hacer_administrador(email)
