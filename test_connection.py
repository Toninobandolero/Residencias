"""
Script simple para probar la conexión y configurar la contraseña.
"""
import os
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError

load_dotenv()

DB_HOST = os.getenv('DB_HOST', '34.155.185.9')
DB_NAME = os.getenv('DB_NAME', 'postgres')
DB_USER = os.getenv('DB_USER', 'postgres')
DB_PORT = os.getenv('DB_PORT', '5432')


def test_and_save_password(password):
    """Prueba la conexión y actualiza el .env si es exitosa."""
    print(f"\nProbando conexión...")
    print(f"  Host: {DB_HOST}")
    print(f"  Base de datos: {DB_NAME}")
    print(f"  Usuario: {DB_USER}")
    print(f"  Puerto: {DB_PORT}")
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=password,
            port=DB_PORT,
            connect_timeout=10
        )
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        
        print("\n✅ ¡Conexión exitosa!")
        print(f"PostgreSQL: {version.split(',')[0]}")
        
        # Actualizar .env
        env_content = f"""# Variables de entorno para el backend Violetas

# Base de datos PostgreSQL (Cloud SQL en GCP)
DB_HOST=34.155.185.9
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD={password}
DB_PORT=5432

# JWT Secret Key
JWT_SECRET_KEY=FaZ7O6pfUWaw0hcsUiELhCHr_pzwiv7sZtP1s8mPPjg
"""
        with open('.env', 'w', encoding='utf-8') as f:
            f.write(env_content)
        
        print("\n✅ Archivo .env actualizado correctamente!")
        print("\nAhora puedes ejecutar:")
        print("  python check_db_info.py")
        print("  python db_utils.py verify")
        
        return True
        
    except OperationalError as e:
        error_msg = str(e)
        print(f"\n❌ Error de conexión:")
        
        if "password authentication failed" in error_msg.lower():
            print("  La contraseña es incorrecta.")
        elif "could not connect" in error_msg.lower() or "timeout" in error_msg.lower():
            print("  No se pudo conectar al servidor.")
            print("  Verifica que la IP esté autorizada en GCP Cloud SQL.")
        else:
            print(f"  {error_msg}")
        
        print("\n💡 Si no recuerdas la contraseña:")
        print("  1. Ve a https://console.cloud.google.com/sql")
        print("  2. Selecciona tu instancia 'residencias'")
        print("  3. Ve a 'Usuarios' → 3 puntos (⋮) → 'Cambiar contraseña'")
        
        return False
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
        return False


if __name__ == '__main__':
    print("\n" + "="*60)
    print("CONFIGURACIÓN DE CONTRASEÑA DE POSTGRESQL")
    print("="*60)
    print("\nConfiguración actual:")
    print(f"  Host: {DB_HOST}")
    print(f"  Base de datos: {DB_NAME}")
    print(f"  Usuario: {DB_USER}")
    print(f"  Puerto: {DB_PORT}")
    print("\n" + "-"*60)
    
    password = input("\nIngresa la contraseña del usuario 'postgres': ").strip()
    
    if not password:
        print("\n⚠️  Debes ingresar una contraseña.")
        print("\nSi no la recuerdas, puedes restablecerla desde GCP:")
        print("  https://console.cloud.google.com/sql")
    else:
        test_and_save_password(password)

