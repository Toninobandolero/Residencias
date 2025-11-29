"""
Script para ayudar a encontrar las credenciales de la base de datos.
Prueba combinaciones comunes y guía al usuario.
"""
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError

load_dotenv()

# Valores conocidos
DB_HOST = os.getenv('DB_HOST', '34.155.185.9')
DB_PORT = os.getenv('DB_PORT', '5432')

# Combinaciones comunes a probar
COMMON_DB_NAMES = ['postgres', 'residencias', 'violetas', 'database', 'db']
COMMON_USERS = ['postgres', 'residencias', 'violetas', 'admin', 'user']


def test_connection(db_name, db_user, db_password):
    """Prueba una conexión con las credenciales dadas."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=db_name,
            user=db_user,
            password=db_password,
            port=DB_PORT,
            connect_timeout=5
        )
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        cursor.close()
        conn.close()
        return True, version[0]
    except OperationalError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def list_databases(db_name, db_user, db_password):
    """Lista las bases de datos disponibles."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=db_name,
            user=db_user,
            password=db_password,
            port=DB_PORT,
            connect_timeout=5
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT datname 
            FROM pg_database 
            WHERE datistemplate = false
            ORDER BY datname
        """)
        databases = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return True, databases
    except Exception as e:
        return False, str(e)


def list_users(db_name, db_user, db_password):
    """Lista los usuarios disponibles."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=db_name,
            user=db_user,
            password=db_password,
            port=DB_PORT,
            connect_timeout=5
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT usename 
            FROM pg_user 
            ORDER BY usename
        """)
        users = [row[0] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return True, users
    except Exception as e:
        return False, str(e)


def interactive_setup():
    """Modo interactivo para configurar las credenciales."""
    print("\n" + "="*60)
    print("CONFIGURACIÓN DE CREDENCIALES DE BASE DE DATOS")
    print("="*60)
    print(f"\nHost: {DB_HOST}")
    print(f"Puerto: {DB_PORT}\n")
    
    print("Vamos a probar algunas combinaciones comunes...")
    print("Si ninguna funciona, te guiaré para obtenerlas desde GCP.\n")
    
    # Pedir datos al usuario
    db_name = input("Nombre de la base de datos (o presiona Enter para probar 'postgres'): ").strip()
    if not db_name:
        db_name = 'postgres'
    
    db_user = input("Usuario (o presiona Enter para probar 'postgres'): ").strip()
    if not db_user:
        db_user = 'postgres'
    
    db_password = input("Contraseña: ").strip()
    
    if not db_password:
        print("\n⚠️  Necesitas la contraseña para continuar.")
        print("\nPara obtenerla o restablecerla:")
        print("1. Ve a https://console.cloud.google.com/sql")
        print("2. Selecciona tu instancia 'residencias'")
        print("3. Haz clic en 'Usuarios' en el menú lateral")
        print("4. Si ves el usuario, haz clic en los 3 puntos → 'Cambiar contraseña'")
        return
    
    print(f"\nProbando conexión con:")
    print(f"  Base de datos: {db_name}")
    print(f"  Usuario: {db_user}")
    print(f"  Contraseña: {'*' * len(db_password)}")
    print("\nConectando...")
    
    success, result = test_connection(db_name, db_user, db_password)
    
    if success:
        print("\n✅ ¡Conexión exitosa!")
        print(f"Versión de PostgreSQL: {result[:50]}...")
        
        # Listar bases de datos disponibles
        print("\nBases de datos disponibles:")
        success_db, databases = list_databases(db_name, db_user, db_password)
        if success_db:
            for db in databases:
                print(f"  - {db}")
        
        # Listar usuarios
        print("\nUsuarios disponibles:")
        success_usr, users = list_users(db_name, db_user, db_password)
        if success_usr:
            for usr in users:
                print(f"  - {usr}")
        
        # Actualizar .env
        print("\n" + "="*60)
        update = input("¿Actualizar el archivo .env con estas credenciales? (s/n): ").strip().lower()
        if update == 's':
            update_env_file(db_name, db_user, db_password)
            print("\n✅ Archivo .env actualizado correctamente!")
            print("\nAhora puedes ejecutar:")
            print("  python check_db_info.py")
            print("  python db_utils.py verify")
    else:
        print(f"\n❌ Error de conexión: {result}")
        print("\nPosibles causas:")
        print("  1. Contraseña incorrecta")
        print("  2. Nombre de base de datos incorrecto")
        print("  3. Usuario incorrecto")
        print("  4. La IP no está autorizada (revisa en GCP → Cloud SQL → Autorizar redes)")
        
        # Sugerir probar otras combinaciones
        print("\n¿Quieres probar otras combinaciones? (s/n): ", end='')
        if input().strip().lower() == 's':
            try_common_combinations(db_password)


def try_common_combinations(password):
    """Prueba combinaciones comunes de nombres de BD y usuarios."""
    print("\nProbando combinaciones comunes...")
    for db_name in COMMON_DB_NAMES:
        for db_user in COMMON_USERS:
            print(f"Probando: BD={db_name}, Usuario={db_user}...", end=' ')
            success, _ = test_connection(db_name, db_user, password)
            if success:
                print("✅ ¡ÉXITO!")
                print(f"\nCredenciales correctas:")
                print(f"  DB_NAME={db_name}")
                print(f"  DB_USER={db_user}")
                update = input("\n¿Actualizar .env? (s/n): ").strip().lower()
                if update == 's':
                    update_env_file(db_name, db_user, password)
                return
            else:
                print("❌")
    print("\nNo se encontraron combinaciones válidas.")


def update_env_file(db_name, db_user, db_password):
    """Actualiza el archivo .env con las credenciales."""
    env_content = f"""# Variables de entorno para el backend Violetas

# Base de datos PostgreSQL (Cloud SQL en GCP)
DB_HOST=34.155.185.9
DB_NAME={db_name}
DB_USER={db_user}
DB_PASSWORD={db_password}
DB_PORT=5432

# JWT Secret Key
JWT_SECRET_KEY=FaZ7O6pfUWaw0hcsUiELhCHr_pzwiv7sZtP1s8mPPjg
"""
    with open('.env', 'w', encoding='utf-8') as f:
        f.write(env_content)


if __name__ == '__main__':
    print("\n🔍 Asistente para encontrar credenciales de PostgreSQL")
    print("="*60)
    interactive_setup()

