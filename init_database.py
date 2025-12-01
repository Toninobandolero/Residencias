"""
Script de inicialización de base de datos.
Crea el primer usuario super_admin directamente en la BD.
NUNCA se debe crear a través de la API.
"""
from werkzeug.security import generate_password_hash
from db_connector import get_db_connection
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def init_super_admin():
    """
    Crea el primer usuario super_admin en la base de datos.
    Solo debe ejecutarse una vez durante la inicialización.
    """
    # Email y contraseña del super_admin inicial (desde variables de entorno)
    SUPER_ADMIN_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'admin@residencias.com')
    SUPER_ADMIN_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', 'CambiarContraseña123!')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar si ya existe el super_admin
        cursor.execute(
            "SELECT id_usuario FROM usuario WHERE id_rol = 1 AND email = %s",
            (SUPER_ADMIN_EMAIL,)
        )
        if cursor.fetchone():
            print(f"El super_admin {SUPER_ADMIN_EMAIL} ya existe. No se creará duplicado.")
            return
        
        # Verificar que el rol super_admin (id_rol = 1) existe
        cursor.execute("SELECT id_rol FROM rol WHERE id_rol = 1")
        if not cursor.fetchone():
            print("ERROR: El rol super_admin (id_rol = 1) no existe en la tabla 'rol'.")
            print("Por favor, asegúrate de que el rol existe antes de ejecutar este script.")
            return
        
        # Generar hash de la contraseña
        password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
        
        # Insertar el super_admin
        cursor.execute("""
            INSERT INTO usuario (email, password_hash, id_rol, requiere_cambio_clave)
            VALUES (%s, %s, 1, TRUE)
            RETURNING id_usuario
        """, (SUPER_ADMIN_EMAIL, password_hash))
        
        id_usuario = cursor.fetchone()[0]
        conn.commit()
        
        print("="*50)
        print("SUPER ADMIN CREADO EXITOSAMENTE")
        print("="*50)
        print(f"Email: {SUPER_ADMIN_EMAIL}")
        print(f"ID Usuario: {id_usuario}")
        print(f"Rol: Super Administrador (id_rol = 1)")
        print(f"IMPORTANTE: Requiere cambio de contraseña en primer login")
        print("="*50)
        print("\nNOTA: Este usuario NO tiene residencias asignadas (acceso total)")
        print("Para asignar residencias específicas, usa el endpoint POST /api/v1/usuarios")
        print("después del login.\n")
        
    except Exception as e:
        conn.rollback()
        print(f"Error al crear super_admin: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    print("\nInicializando super_admin...")
    init_super_admin()
    print("\nProceso completado.\n")

