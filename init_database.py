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
        # 1. Verificar y agregar columna requiere_cambio_clave si no existe
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'usuario' AND column_name = 'requiere_cambio_clave'
        """)
        if not cursor.fetchone():
            print("⚠️  Agregando columna 'requiere_cambio_clave' a tabla usuario...")
            cursor.execute("""
                ALTER TABLE usuario 
                ADD COLUMN requiere_cambio_clave BOOLEAN DEFAULT TRUE
            """)
            conn.commit()
            print("✅ Columna 'requiere_cambio_clave' agregada")
        
        # 2. Verificar si id_residencia es NOT NULL y hacerla nullable para super_admin
        cursor.execute("""
            SELECT column_name, is_nullable
            FROM information_schema.columns 
            WHERE table_name = 'usuario' AND column_name = 'id_residencia'
        """)
        id_residencia_col = cursor.fetchone()
        if id_residencia_col and id_residencia_col[1] == 'NO':
            print("⚠️  La columna 'id_residencia' es NOT NULL. Permitindo NULL para super_admin...")
            cursor.execute("""
                ALTER TABLE usuario 
                ALTER COLUMN id_residencia DROP NOT NULL
            """)
            conn.commit()
            print("✅ Columna 'id_residencia' ahora permite NULL")
        
        # 3. Verificar si ya existe el super_admin
        cursor.execute(
            "SELECT id_usuario FROM usuario WHERE id_rol = 1 AND email = %s",
            (SUPER_ADMIN_EMAIL,)
        )
        if cursor.fetchone():
            print(f"El super_admin {SUPER_ADMIN_EMAIL} ya existe. No se creará duplicado.")
            return
        
        # Verificar que el rol super_admin (id_rol = 1) existe, si no existe, crearlo
        cursor.execute("SELECT id_rol, nombre FROM rol WHERE id_rol = 1")
        rol_existente = cursor.fetchone()
        if not rol_existente:
            print("⚠️  El rol super_admin (id_rol = 1) no existe. Creándolo...")
            cursor.execute("""
                INSERT INTO rol (id_rol, nombre, descripcion, activo)
                VALUES (1, 'super_admin', 'Super Administrador con acceso total', TRUE)
                ON CONFLICT (id_rol) DO NOTHING
                RETURNING id_rol
            """)
            if cursor.fetchone():
                conn.commit()
                print("✅ Rol super_admin creado exitosamente")
            else:
                print("⚠️  El rol ya existe pero con otro nombre. Continuando...")
        else:
            # Actualizar el nombre del rol si no es 'super_admin'
            if rol_existente[1] != 'super_admin':
                print(f"⚠️  El rol con id_rol=1 se llama '{rol_existente[1]}'. Actualizando a 'super_admin'...")
                cursor.execute("""
                    UPDATE rol 
                    SET nombre = 'super_admin', 
                        descripcion = 'Super Administrador con acceso total'
                    WHERE id_rol = 1
                """)
                conn.commit()
                print("✅ Nombre del rol actualizado a 'super_admin'")
        
        # Generar hash de la contraseña
        password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
        
        # Insertar el super_admin (sin id_residencia para acceso total)
        # Verificar si la columna id_residencia existe
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'usuario' AND column_name = 'id_residencia'
        """)
        tiene_id_residencia = cursor.fetchone() is not None
        
        if tiene_id_residencia:
            # Si la columna existe, insertar con NULL (acceso total)
            cursor.execute("""
                INSERT INTO usuario (email, password_hash, id_rol, requiere_cambio_clave, id_residencia)
                VALUES (%s, %s, 1, TRUE, NULL)
                RETURNING id_usuario
            """, (SUPER_ADMIN_EMAIL, password_hash))
        else:
            # Si la columna no existe (ya fue migrada), insertar sin ella
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

