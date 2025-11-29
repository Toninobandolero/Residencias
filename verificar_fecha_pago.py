import os
import sys
from dotenv import load_dotenv
import psycopg2
from psycopg2 import OperationalError

load_dotenv()

def verificar_fecha_pago():
    """Verifica si fecha_pago permite NULL."""
    print("Verificando restricción de fecha_pago...\n")
    
    db_host = os.getenv('DB_HOST')
    db_name = os.getenv('DB_NAME')
    db_user = os.getenv('DB_USER')
    db_password = os.getenv('DB_PASSWORD')
    db_port = os.getenv('DB_PORT', '5432')

    if not all([db_host, db_name, db_user, db_password]):
        print("❌ Error: Faltan variables de entorno requeridas")
        sys.exit(1)

    conn = None
    cursor = None
    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password,
            port=db_port,
            connect_timeout=10
        )
        cursor = conn.cursor()
        
        # Verificar la definición de la columna
        cursor.execute("""
            SELECT column_name, is_nullable, data_type, column_default
            FROM information_schema.columns
            WHERE table_name = 'pago_residente' AND column_name = 'fecha_pago'
        """)
        
        columna = cursor.fetchone()
        
        if columna:
            print(f"Columna: {columna[0]}")
            print(f"Permite NULL: {columna[1]}")
            print(f"Tipo: {columna[2]}")
            print(f"Default: {columna[3]}")
            
            if columna[1] == 'NO':
                print("\n❌ La columna NO permite NULL. Intentando corregir...")
                try:
                    cursor.execute("ALTER TABLE pago_residente ALTER COLUMN fecha_pago DROP NOT NULL")
                    conn.commit()
                    print("✅ Restricción eliminada correctamente")
                except Exception as e:
                    print(f"❌ Error al eliminar restricción: {e}")
                    conn.rollback()
            else:
                print("\n✅ La columna YA permite NULL")
        else:
            print("❌ No se encontró la columna fecha_pago")
        
    except OperationalError as e:
        print(f"❌ Error de conexión: {e}")
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    verificar_fecha_pago()

