"""
Utilidades para la base de datos.
Incluye funciones para hashear contraseñas y crear usuarios.
"""
import os
from werkzeug.security import generate_password_hash
from db_connector import get_db_connection
from dotenv import load_dotenv

load_dotenv()


def hash_password(password):
    """
    Genera un hash seguro de una contraseña usando Werkzeug.
    
    Args:
        password (str): Contraseña en texto plano
        
    Returns:
        str: Contraseña hasheada
    """
    return generate_password_hash(password)


def create_user(email, password, id_rol, id_residencia):
    """
    Crea un nuevo usuario en la base de datos.
    
    Args:
        email (str): Email del usuario
        password (str): Contraseña en texto plano (se hasheará)
        id_rol (int): ID del rol del usuario
        id_residencia (int): ID de la residencia (1 para Violetas 1, 2 para Violetas 2)
        
    Returns:
        int: ID del usuario creado
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        
        cursor.execute(
            """
            INSERT INTO usuario (email, password_hash, id_rol, id_residencia)
            VALUES (%s, %s, %s, %s)
            RETURNING id_usuario
            """,
            (email, password_hash, id_rol, id_residencia)
        )
        
        id_usuario = cursor.fetchone()[0]
        conn.commit()
        
        print(f"Usuario creado exitosamente:")
        print(f"  ID: {id_usuario}")
        print(f"  Email: {email}")
        print(f"  Rol ID: {id_rol}")
        print(f"  Residencia ID: {id_residencia}")
        
        return id_usuario
        
    except Exception as e:
        conn.rollback()
        print(f"Error al crear usuario: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()


def verify_table_structure():
    """
    Verifica que la tabla usuario tenga la estructura correcta.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'usuario'
            ORDER BY ordinal_position
        """)
        
        columns = cursor.fetchall()
        
        required_columns = {
            'id_usuario': 'integer',
            'email': 'character varying',
            'password_hash': 'character varying',
            'id_rol': 'integer',
            'id_residencia': 'integer'
        }
        
        print("Estructura de la tabla 'usuario':")
        print("-" * 50)
        
        found_columns = {}
        for col_name, data_type, is_nullable in columns:
            found_columns[col_name] = data_type
            nullable = "NULL" if is_nullable == 'YES' else "NOT NULL"
            print(f"  {col_name}: {data_type} ({nullable})")
        
        print("\nVerificación de columnas requeridas:")
        all_present = True
        for col, expected_type in required_columns.items():
            if col in found_columns:
                print(f"  ✓ {col} - presente")
            else:
                print(f"  ✗ {col} - FALTANTE")
                all_present = False
        
        if all_present:
            print("\n✓ La tabla tiene la estructura correcta")
        else:
            print("\n✗ Faltan columnas requeridas")
            
        return all_present
        
    except Exception as e:
        print(f"Error al verificar estructura: {str(e)}")
        return False
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python db_utils.py hash <contraseña>  - Hashea una contraseña")
        print("  python db_utils.py create <email> <password> <id_rol> <id_residencia>  - Crea un usuario")
        print("  python db_utils.py verify  - Verifica la estructura de la tabla usuario")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'hash':
        if len(sys.argv) < 3:
            print("Error: Proporciona una contraseña")
            sys.exit(1)
        password = sys.argv[2]
        print(f"Hash de contraseña: {hash_password(password)}")
        
    elif command == 'create':
        if len(sys.argv) < 6:
            print("Error: Uso: python db_utils.py create <email> <password> <id_rol> <id_residencia>")
            sys.exit(1)
        email = sys.argv[2]
        password = sys.argv[3]
        id_rol = int(sys.argv[4])
        id_residencia = int(sys.argv[5])
        create_user(email, password, id_rol, id_residencia)
        
    elif command == 'verify':
        verify_table_structure()
    else:
        print(f"Comando desconocido: {command}")

