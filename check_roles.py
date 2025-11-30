
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

def check_roles():
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            port=os.getenv('DB_PORT', '5432'),
            connect_timeout=10
        )
        cursor = conn.cursor()
        
        print("--- ROLES ---")
        cursor.execute("SELECT * FROM rol ORDER BY id_rol")
        for row in cursor.fetchall():
            print(f"ID: {row[0]}, Nombre: {row[1]}")
            
        print("\n--- USUARIO ACTUAL (ejemplo) ---")
        # Check the first user to see what role they have
        cursor.execute("SELECT id_usuario, email, id_rol, id_residencia FROM usuario LIMIT 5")
        for row in cursor.fetchall():
            print(f"User: {row[1]}, Rol: {row[2]}, Residencia: {row[3]}")

        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_roles()

