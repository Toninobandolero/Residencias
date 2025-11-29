"""
Script para consultar información de la base de datos.
Útil para obtener IDs de residencias, roles, y verificar usuarios.
"""
from db_connector import get_db_connection
from dotenv import load_dotenv

load_dotenv()


def check_residencias():
    """Muestra todas las residencias disponibles."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id_residencia, nombre FROM residencia ORDER BY id_residencia")
        residencias = cursor.fetchall()
        
        print("\n" + "="*50)
        print("RESIDENCIAS")
        print("="*50)
        if residencias:
            for id_res, nombre in residencias:
                print(f"  ID: {id_res} - {nombre}")
        else:
            print("  No se encontraron residencias")
        print()
        
    except Exception as e:
        print(f"Error al consultar residencias: {str(e)}")
    finally:
        cursor.close()
        conn.close()


def check_roles():
    """Muestra todos los roles disponibles."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id_rol, nombre FROM rol ORDER BY id_rol")
        roles = cursor.fetchall()
        
        print("\n" + "="*50)
        print("ROLES")
        print("="*50)
        if roles:
            for id_rol, nombre in roles:
                print(f"  ID: {id_rol} - {nombre}")
        else:
            print("  No se encontraron roles")
        print()
        
    except Exception as e:
        print(f"Error al consultar roles: {str(e)}")
    finally:
        cursor.close()
        conn.close()


def check_usuarios():
    """Muestra todos los usuarios (sin contraseñas)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id_usuario, email, id_rol, id_residencia 
            FROM usuario 
            ORDER BY id_usuario
        """)
        usuarios = cursor.fetchall()
        
        print("\n" + "="*50)
        print("USUARIOS")
        print("="*50)
        if usuarios:
            print(f"{'ID':<5} {'Email':<30} {'Rol ID':<8} {'Residencia ID':<15}")
            print("-" * 60)
            for id_user, email, id_rol, id_res in usuarios:
                print(f"{id_user:<5} {email:<30} {id_rol:<8} {id_res:<15}")
        else:
            print("  No se encontraron usuarios")
        print()
        
    except Exception as e:
        print(f"Error al consultar usuarios: {str(e)}")
    finally:
        cursor.close()
        conn.close()


def check_all():
    """Muestra toda la información de la base de datos."""
    print("\n" + "="*50)
    print("INFORMACIÓN DE LA BASE DE DATOS")
    print("="*50)
    
    try:
        check_residencias()
        check_roles()
        check_usuarios()
    except Exception as e:
        print(f"\nError de conexión: {str(e)}")
        print("\nAsegúrate de que:")
        print("  1. Las credenciales en .env sean correctas")
        print("  2. La base de datos esté accesible")
        print("  3. Las tablas existan en la base de datos")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == 'residencias':
            check_residencias()
        elif command == 'roles':
            check_roles()
        elif command == 'usuarios':
            check_usuarios()
        else:
            print("Uso: python check_db_info.py [residencias|roles|usuarios]")
            print("     Sin argumentos muestra toda la información")
    else:
        check_all()

